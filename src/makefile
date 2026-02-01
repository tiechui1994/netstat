# 定义程序名称
TARGET = traffic_monitor

# 源代码文件
SRC = mini_traffic.c

# 编译选项
# -Os: 专门针对存储受限环境优化体积
# -Wall: 开启所有警告
# -static: 如果目标平台缺少库，可以考虑开启（但会增加体积）
CFLAGS = -Os -Wall -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector \
 -Wl,--gc-sections -Wl,--build-id=none

# 交叉编译器定义 (请根据您实际的交叉编译工具链名称修改)
CC_AMD64 = gcc
CC_ARM7  = arm-linux-musleabi-gcc
CC_ARM64 = aarch64-linux-musl-gcc

STRIP_AMD64 = strip
STRIP_ARM7 = arm-linux-musleabi-strip
STRIP_ARM64 = aarch64-linux-musl-strip

# 默认输出目录
OUTPUT_DIR = build

.PHONY: all clean help amd64 arm7 arm64

# 默认编译所有版本
all: amd64 arm7 arm64

# AMD64 版本 (本地 Linux)
amd64:
	@mkdir -p $(OUTPUT_DIR)
	$(CC_AMD64) $(CFLAGS) $(SRC) -o $(OUTPUT_DIR)/$(TARGET)_amd64
	$(STRIP_AMD64) $(OUTPUT_DIR)/$(TARGET)_amd64
	@echo "Build AMD64 done."

# ARM7 版本 (适配您的 Linux 3.14 裁剪内核)
arm7:
	@mkdir -p $(OUTPUT_DIR)
	$(CC_ARM7) -static $(CFLAGS) -DTARGET_ARM7 $(SRC) -o $(OUTPUT_DIR)/$(TARGET)_arm7
	$(STRIP_ARM7) -S --strip-unneeded $(OUTPUT_DIR)/$(TARGET)_arm7
	@echo "Build ARM7 done."

# ARM64 版本
arm64:
	@mkdir -p $(OUTPUT_DIR)
	$(CC_ARM64) -static $(CFLAGS) $(SRC) -o $(OUTPUT_DIR)/$(TARGET)_arm64
	$(STRIP_ARM64) $(OUTPUT_DIR)/$(TARGET)_arm64
	@echo "Build ARM64 done."

# 清理
clean:
	rm -rf $(OUTPUT_DIR)
	@echo "Cleaned."

help:
	@echo "Usage:"
	@echo "  make         - Build for all architectures"
	@echo "  make arm7    - Build for ARM7 (Linux 3.14)"
	@echo "  make amd64   - Build for local PC"
	@echo "  make arm64   - Build for ARM64"
	@echo "  make clean   - Remove build directory"