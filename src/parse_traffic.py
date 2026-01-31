import struct
import socket
import sys

# 格式说明：< 小端, I uint32, 6B mac, I uint32, I uint32 (总18字节)
RECORD_FORMAT = "<I6BII"
RECORD_SIZE = struct.calcsize(RECORD_FORMAT)

def parse(file_path):
    try:
        with open(file_path, "rb") as f:
            print(f"{'Source IP':<15} | {'Source MAC':<17} | {'TCP Bytes':<12} | {'UDP Bytes':<12}")
            print("-" * 65)
            while True:
                chunk = f.read(RECORD_SIZE)
                if len(chunk) < RECORD_SIZE: break
                
                data = struct.unpack(RECORD_FORMAT, chunk)
                ip = socket.inet_ntoa(struct.pack("<I", data[0]))
                mac = ":".join(f"{b:02x}" for b in data[1:7])
                tcp, udp = data[7], data[8]
                
                print(f"{ip:<15} | {mac:<17} | {tcp:<12} | {udp:<12}")
    except FileNotFoundError:
        print("File not found.")

if __name__ == "__main__":
    parse(sys.argv[1] if len(sys.argv) > 1 else "traffic.bin")