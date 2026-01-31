# netstat - Lightweight Traffic Monitor 🚦

**简要说明**

一个简单的流量监控工具（单文件 C 程序），提供最小化的二进制以便在多种 Linux 平台运行与交叉编译。

---

## 特性 ✅

- 极小体积，适合嵌入式或裁剪内核环境
- 支持构建三种平台：`amd64`、`arm64`、`arm7`
- 提供 GitHub Actions 多架构构建并上传构建产物

---

## 快速开始 🔧

在本仓库根目录运行（需要已安装对应编译器）：

- 构建所有平台：

```sh
make -C src
```

- 构建单个平台：

```shn
make -C src amd64   # 本机 x86_64
make -C src arm64   # ARM64 (aarch64)
make -C src arm7    # ARMv7 (gnueabihf)
```

- 清理构建产物：

```sh
make -C src clean
```

构建输出位于 `src/build/`，文件名类似 `traffic_monitor_amd64` / `traffic_monitor_arm64` / `traffic_monitor_arm7`。

---

## CI (GitHub Actions) 🛠️

仓库包含 workflow：`.github/workflows/build.yml`，会在 `push` / `pull_request` 到 `main` 时触发，自动在 `amd64`、`arm64`、`arm7` 上构建并上传 `src/build/` 下的产物为 artifact。

---

## 依赖（示例）📦

- 本地 amd64: `build-essential`
- arm64 交叉编译器: `gcc-aarch64-linux-gnu`、`binutils-aarch64-linux-gnu`
- arm7 交叉编译器: `gcc-arm-linux-gnueabihf`、`binutils-arm-linux-gnueabihf`

例如在 Ubuntu 上：

```sh
sudo apt-get update
sudo apt-get install -y build-essential gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf binutils-aarch64-linux-gnu binutils-arm-linux-gnueabihf
```

---

## 使用举例 ▶️

```sh
# 运行本地构建的 amd64 可执行文件
./src/build/traffic_monitor_amd64
```

（注意：程序可能需要额外权限来访问网络/系统信息，需根据运行环境决定是否用 `sudo`）

---

## 许可证 📜

本项目使用 `LICENSE` 文件中的许可证。

---

## 贡献与反馈 💬

欢迎通过 Issue 或 Pull Request 提交问题、建议或改进。