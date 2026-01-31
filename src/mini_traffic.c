#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>

/* --- 配置参数 --- */
#define STORAGE_QUOTA_BYTES 92160     
#define LOG_FILE            "traffic.bin"
#define HASH_SIZE           256
#define MAX_NODES           256
#define REPORT_INTERVAL     1800      
#define MAX_RETRIES         3         

#define BLOCK_SIZE 4096
#define BLOCK_NR   16
#define FRAME_SIZE 2048
#define FRAME_NR   ((BLOCK_SIZE * BLOCK_NR) / FRAME_SIZE)

typedef struct __attribute__((packed)) {
    uint32_t ip;
    uint8_t  mac[6];
    uint32_t tcp_bytes;
    uint32_t udp_bytes;
} bin_record_t;

typedef struct traffic_node {
    bin_record_t data;
    struct traffic_node *next;
} traffic_node_t;

static traffic_node_t* hash_table[HASH_SIZE];
static int total_nodes = 0;
static time_t last_report_time = 0;
static volatile int keep_running = 1;
static char *report_url = NULL;

int is_private_ip(uint32_t ip_h) {
    if ((ip_h & 0xFF000000) == 0x0A000000) return 1;
    if ((ip_h & 0xFFF00000) == 0xAC100000) return 1;
    if ((ip_h & 0xFFFF0000) == 0xC0A80000) return 1;
    if ((ip_h & 0xFF000000) == 0x7F000000) return 1;
    return 0;
}

void handle_exit(int sig) { 
    keep_running = 0; 
}

/* --- HTTP JSON 上报 (增加详细报错) --- */
int http_post_json(const char *json_data) {
    if (!report_url) return 0;
    char host[64] = {0};
    int port = 80;
    char *colon = strchr(report_url, ':');
    if (colon) {
        strncpy(host, report_url, colon - report_url);
        port = atoi(colon + 1);
    } else {
        strcpy(host, report_url);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[HTTP Error] Socket create failed: %s\n", strerror(errno));
        return -1;
    }

    struct timeval timeout = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct hostent *server = gethostbyname(host);
    if (!server) {
        fprintf(stderr, "[HTTP Error] DNS lookup failed for %s\n", host);
        close(sock); return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
    addr.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[HTTP Error] Connect to %s:%d failed: %s\n", host, port, strerror(errno));
        close(sock); return -1;
    }

    char header[512];
    int content_len = strlen(json_data);
    snprintf(header, sizeof(header),
             "POST /report HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n\r\n", host, content_len);

    if (send(sock, header, strlen(header), 0) < 0 || send(sock, json_data, content_len, 0) < 0) {
        fprintf(stderr, "[HTTP Error] Data send failed: %s\n", strerror(errno));
        close(sock); return -1;
    }

    char resp[256] = {0};
    int n = recv(sock, resp, sizeof(resp)-1, 0);
    close(sock);

    if (n > 0 && strstr(resp, "200 OK")) return 0;
    
    fprintf(stderr, "[HTTP Warn] Server response error or not 200 OK. Response: %.50s...\n", n > 0 ? resp : "NULL");
    return -1;
}

void process_cycle(int is_final) {
    if (total_nodes == 0) return;

    bin_record_t *records = malloc(total_nodes * sizeof(bin_record_t));
    char *json_buf = malloc(total_nodes * 96 + 128);
    if (!records || !json_buf) {
        fprintf(stderr, "[Fatal Error] Memory allocation failed during cycle processing!\n");
        if (records) free(records);
        if (json_buf) free(json_buf);
        return;
    }

    char *p = json_buf;
    p += sprintf(p, "[");

    int count = 0;
    for (int i = 0; i < HASH_SIZE; i++) {
        traffic_node_t *curr = hash_table[i];
        while (curr) {
            records[count++] = curr->data;
            struct in_addr ip_addr = { .s_addr = curr->data.ip };
            p += sprintf(p, "{\"ip\":\"%s\",\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"tcp\":%u,\"udp\":%u}",
                        inet_ntoa(ip_addr),
                        curr->data.mac[0], curr->data.mac[1], curr->data.mac[2],
                        curr->data.mac[3], curr->data.mac[4], curr->data.mac[5],
                        curr->data.tcp_bytes, curr->data.udp_bytes);
            
            traffic_node_t *tmp = curr;
            curr = curr->next;
            free(tmp);
            if (curr || count < total_nodes) p += sprintf(p, ",");
        }
        hash_table[i] = NULL;
    }
    sprintf(p, "]");

    // 本地 Flash 存储
    FILE *fp = fopen(LOG_FILE, "ab");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        if (ftell(fp) < STORAGE_QUOTA_BYTES) {
            if (fwrite(records, sizeof(bin_record_t), count, fp) != count) {
                fprintf(stderr, "[Storage Error] Binary write failed: %s\n", strerror(errno));
            }
        } else {
            fprintf(stderr, "[Storage Warn] Log file %s exceeded quota (%d KB). Writing skipped.\n", LOG_FILE, STORAGE_QUOTA_BYTES/1024);
        }
        fclose(fp);
    } else {
        fprintf(stderr, "[Storage Error] Cannot open %s for append: %s\n", LOG_FILE, strerror(errno));
    }

    // HTTP 上报
    if (report_url) {
        int retries = 0;
        while (retries < MAX_RETRIES) {
            if (http_post_json(json_buf) == 0) {
                printf("[Success] Reported %d records to %s\n", count, report_url);
                break;
            }
            retries++;
            fprintf(stderr, "[HTTP Retry] Attempt %d/%d for URL %s\n", retries, MAX_RETRIES, report_url);
            if (!is_final) sleep(5);
        }
    }

    free(records);
    free(json_buf);
    total_nodes = 0;
}

void update_stats(uint32_t ip_n, uint8_t *mac, uint32_t len, int proto) {
    uint32_t idx = (ip_n ^ (ip_n >> 16)) & (HASH_SIZE - 1);
    traffic_node_t *curr = hash_table[idx];
    while (curr) {
        if (curr->data.ip == ip_n) {
            if (proto == IPPROTO_TCP) curr->data.tcp_bytes += len;
            else if (proto == IPPROTO_UDP) curr->data.udp_bytes += len;
            return;
        }
        curr = curr->next;
    }
    if (total_nodes < MAX_NODES) {
        traffic_node_t *node = calloc(1, sizeof(traffic_node_t));
        if (node) {
            node->data.ip = ip_n;
            memcpy(node->data.mac, mac, 6);
            if (proto == IPPROTO_TCP) node->data.tcp_bytes = len;
            else if (proto == IPPROTO_UDP) node->data.udp_bytes = len;
            node->next = hash_table[idx];
            hash_table[idx] = node;
            total_nodes++;
        } else {
            fprintf(stderr, "[Memory Warn] Node allocation failed. Skipping new IP.\n");
        }
    }
}

int main(int argc, char **argv) {
    if (argc > 1) report_url = argv[1];
    
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    // 必须以 root 运行
    if (getuid() != 0) {
        fprintf(stderr, "[Fatal Error] This program must be run as root to capture packets.\n");
        return 1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr, "[Fatal Error] Socket creation failed: %s\n", strerror(errno));
        return 1;
    }

    struct tpacket_req req = {
        .tp_block_size = BLOCK_SIZE,
        .tp_block_nr   = BLOCK_NR,
        .tp_frame_size = FRAME_SIZE,
        .tp_frame_nr   = FRAME_NR
    };

    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        fprintf(stderr, "[Fatal Error] setsockopt RX_RING failed: %s\n", strerror(errno));
        close(fd); return 1;
    }

    uint8_t *map = mmap(NULL, BLOCK_SIZE * BLOCK_NR, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "[Fatal Error] mmap failed: %s\n", strerror(errno));
        close(fd); return 1;
    }

    struct iovec rd[FRAME_NR];
    for (int i = 0; i < FRAME_NR; i++) rd[i].iov_base = map + (i * FRAME_SIZE);

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int offset = 0;
    last_report_time = time(NULL);

    printf("[System] Monitor active. URL: %s, Storage: %s\n", report_url ? report_url : "Local Only", LOG_FILE);

    while (keep_running) {
        struct tpacket_hdr *hdr = rd[offset].iov_base;
        if (!(hdr->tp_status & TP_STATUS_USER)) {
            if (time(NULL) - last_report_time >= REPORT_INTERVAL) {
                process_cycle(0);
                last_report_time = time(NULL);
            }
            if (poll(&pfd, 1, 1000) < 0 && errno != EINTR) {
                fprintf(stderr, "[System Error] Poll failed: %s\n", strerror(errno));
            }
            continue;
        }
        uint8_t *pkt = (uint8_t *)hdr + hdr->tp_mac;
        struct ethhdr *eth = (struct ethhdr *)pkt;
        if (ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr *iph = (struct iphdr *)(pkt + sizeof(struct ethhdr));
            if (is_private_ip(ntohl(iph->saddr)) && !is_private_ip(ntohl(iph->daddr))) {
                update_stats(iph->saddr, eth->h_source, ntohs(iph->tot_len), iph->protocol);
            }
        }
        hdr->tp_status = TP_STATUS_KERNEL;
        offset = (offset + 1) % FRAME_NR;
    }

    printf("[System] Signal received. Cleaning up...\n");
    process_cycle(1);
    munmap(map, BLOCK_SIZE * BLOCK_NR);
    close(fd);
    return 0;
}