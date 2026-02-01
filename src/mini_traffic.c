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
#include <arpa/inet.h>

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

void handle_exit(int sig) { keep_running = 0; }

/**
 * http_post_json - 发送 JSON 报文到指定服务器
 * @json_data: 需要发送的 JSON 字符串内容
 * * 在 TARGET_ARM7 宏启用时，report_url 必须为 "IP:PORT" 格式。
 * 在其他架构下，支持 "HOSTNAME:PORT" 格式。
 */
int http_post_json(const char *json_data) {
    if (!report_url || !json_data) return -1;

    char host[64] = {0};
    int port = 80;
    char *colon = strchr(report_url, ':');

    // 解析 Host 和 Port
    if (colon) {
        size_t host_len = (size_t)(colon - report_url);
        if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
        strncpy(host, report_url, host_len);
        port = atoi(colon + 1);
    } else {
        strncpy(host, report_url, sizeof(host) - 1);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[HTTP Error] Socket init failed: %s\n", strerror(errno));
        return -1;
    }

    // 设置收发超时 (10秒)，防止网络卡死阻塞统计主进程
    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // 地址解析逻辑
    int addr_ok = 0;
    if (inet_aton(host, &addr.sin_addr)) {
        addr_ok = 1; // 成功解析为纯 IP 地址
    } else {
#ifdef TARGET_ARM7
        /* ARM7 静态编译模式下禁用 gethostbyname 以极致压缩体积 */
        fprintf(stderr, "[HTTP Error] DNS lookup disabled on ARM7. Use IP instead of '%s'\n", host);
#else
        /* AMD64/ARM64 模式下支持域名解析 */
        struct hostent *server = gethostbyname(host);
        if (server) {
            memcpy(&addr.sin_addr.s_addr, server->h_addr, (size_t)server->h_length);
            addr_ok = 1;
        } else {
            fprintf(stderr, "[HTTP Error] DNS lookup failed for: %s\n", host);
        }
#endif
    }

    if (!addr_ok) {
        close(sock);
        return -1;
    }

    // 建立连接
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[HTTP Error] Connection to %s:%d failed: %s\n", host, port, strerror(errno));
        close(sock);
        return -1;
    }

    // 构造标准的 HTTP POST 报文
    char header[512];
    int content_len = (int)strlen(json_data);
    int head_len = snprintf(header, sizeof(header),
             "POST /report HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n\r\n", 
             host, content_len);

    // 发送 Header 和 Body
    if (send(sock, header, (size_t)head_len, 0) < 0 || 
        send(sock, json_data, (size_t)content_len, 0) < 0) {
        fprintf(stderr, "[HTTP Error] Send failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    // 接收简单的服务器响应 (主要检查 200 OK)
    char resp[256] = {0};
    int n = (int)recv(sock, resp, sizeof(resp) - 1, 0);
    close(sock);

    if (n > 0 && strstr(resp, "200 OK")) {
        return 0; // 上报成功
    }

    fprintf(stderr, "[HTTP Warn] Server rejected report or no response (n=%d)\n", n);
    return -1;
}

/* --- 核心业务逻辑 (process_cycle & update_stats 同前) --- */
void process_cycle(int is_final) {
    if (total_nodes == 0) return;
    bin_record_t *records = malloc(total_nodes * sizeof(bin_record_t));
    char *json_buf = malloc(total_nodes * 128 + 256);
    if (!records || !json_buf) {
        if (records) free(records); 
        if (json_buf) free(json_buf);
        fprintf(stderr, "[Error] Memory allocation failure\n");
        return;
    }
    char *p = json_buf;
    p += sprintf(p, "[");
    int count = 0;
    for (int i = 0; i < HASH_SIZE; i++) {
        traffic_node_t *curr = hash_table[i];
        while (curr) {
            records[count++] = curr->data;
            struct in_addr ia = { .s_addr = curr->data.ip };
            p += sprintf(p, "{\"ip\":\"%s\",\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"tcp\":%u,\"udp\":%u}",
                        inet_ntoa(ia), curr->data.mac[0], curr->data.mac[1], curr->data.mac[2],
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

    FILE *fp = fopen(LOG_FILE, "ab");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        if (ftell(fp) < STORAGE_QUOTA_BYTES) fwrite(records, sizeof(bin_record_t), count, fp);
        fclose(fp);
    }

    if (report_url) {
        int retries = 0;
        while (retries < MAX_RETRIES) {
            if (http_post_json(json_buf) == 0) {
                printf("[OK] Reported %d nodes\n", count);
                break;
            }
            retries++;
            if (!is_final) sleep(5);
        }
    }
    free(records); free(json_buf);
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
            else node->data.udp_bytes = len;
            node->next = hash_table[idx]; hash_table[idx] = node;
            total_nodes++;
        }
    }
}

int main(int argc, char **argv) {
    if (argc > 1) report_url = argv[1];
    if (getuid() != 0) { 
        fprintf(stderr, "Must run as root\n"); 
        return 1; 
    }
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { 
        fprintf(stderr, "[Fatal Error] Socket creation failed: %s\n", strerror(errno)); 
        return 1; 
    }

    struct tpacket_req req = { 
        .tp_block_size = BLOCK_SIZE, 
        .tp_block_nr = BLOCK_NR,
        .tp_frame_size = FRAME_SIZE, 
        .tp_frame_nr = FRAME_NR 
    };
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) { 
        fprintf(stderr, "[Fatal Error] setsockopt RX_RING failed: %s\n", strerror(errno));
        close(fd); return 1;
    }

    uint8_t *map = mmap(NULL, BLOCK_SIZE * BLOCK_NR, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    struct iovec rd[FRAME_NR];
    for (int i = 0; i < FRAME_NR; i++) rd[i].iov_base = map + (i * FRAME_SIZE);

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int offset = 0;
    last_report_time = time(NULL);

    while (keep_running) {
        struct tpacket_hdr *hdr = rd[offset].iov_base;
        if (!(hdr->tp_status & TP_STATUS_USER)) {
            if (time(NULL) - last_report_time >= REPORT_INTERVAL) {
                process_cycle(0);
                last_report_time = time(NULL);
            }
            poll(&pfd, 1, 1000);
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
    process_cycle(1);
    munmap(map, BLOCK_SIZE * BLOCK_NR);
    close(fd);
    return 0;
}