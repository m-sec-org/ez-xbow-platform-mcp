# EZ XBow Challenge MCP

一个用于 AI 驱动的渗透测试竞赛的**模型上下文协议 (MCP)** 服务器。该工具提供了一个完整的 API 接口，使 LLM 能够自主参与 CTF 挑战。

## 特性

- **挑战管理** - 列出、尝试和提交 CTF 挑战的解决方案
- **知识库** - 内建涵盖 9 种漏洞类别的 CTF 技术文档
- **持久化 Kali 容器** - 在隔离环境中执行安全工具（nmap、sqlmap、gobuster 等）
- **尝试历史** - 通过自动笔记管理，跨会话跟踪和共享发现
- **多种协议** - 支持 stdio、SSE 和 HTTP/2 流模式

## 快速开始

### 前提条件

- Go 1.24.7+
- 支持 buildx 的 Docker

### 构建

```bash
go build -o xbow-mcp ./cmd/main.go
```

### 使用模拟平台运行（测试）

在 `./mock-challenges` 中根据模板创建相应赛题文件。
```json
{
    "challenge_code": "XBEN-123-24",
    "difficulty": "easy",
    "points": 200,
    "target_info": {
        "ip": "192.168.5.37",
        "port": [32820]
    },
    "hint_viewed": false,
    "solved": true,
    "hint_content": "Sometimes the AuthN/AuthZ checks are vulnerable to TOCTOU issues if they are not implemented properly",
    "solution": "flag{xxxx}"
}
```

启动命令

```bash
./xbow-mcp --mock  -listen 127.0.0.1:8080
```

### 使用真实平台运行

```bash
./xbow-mcp \
  -xbow-url https://your-xbow-platform.com \
  -xbow-token YOUR_AUTH_TOKEN \
  -mode streamable \
  -listen 127.0.0.1:8080
```

## 可用工具

| 工具 | 描述 |
|------|-------------|
| `list_challenges` | 获取当前阶段的挑战，包括难度和目标信息 |
| `do_challenge` | 标记挑战为进行中，并增加尝试计数器 |
| `get_challenge_hint` | 检索提示（会扣除分数） |
| `submit_answer` | 提交 Flag 并接收评分结果 |
| `get_ctf_skill` | 访问技术文档（xss、sql、ssti、ssrf、idor、xxe、lfi、codei、afr&pt） |
| `write_challenge_note` | 保存发现和尝试记录，供将来参考 |
| `read_challenge_note` | 查看历史笔记（每 9 次尝试后自动重置） |
| `kail_terminal` | 在持久化 Kali 容器中执行命令 |
| `get_terminal_history` | 通过 ID 检索命令执行结果 |

## 命令行选项

```bash
# 服务器模式
-mode, -m [stdio|sse|streamable]       MCP 服务器协议 (默认: streamable)
-listen, -l ADDR:PORT                  监听地址 (默认: 127.0.0.1:8080)

# 平台配置
-xbow-url, -u URL                      XBow API 基础 URL
-xbow-token, -t TOKEN                  认证 Token

# Docker 配置
-docker-container, -c NAME             容器名称 (默认: xbow-kail)
-docker-image, -i IMAGE:TAG            Docker 镜像 (默认: xbow-kail:latest)
-dockerfile-dir, -f PATH               Dockerfile 路径 (默认: ./Dockerfile)
-docker-exec-log-dir, -d DIR           执行日志目录 (默认: ./.kail-history)

# 模拟平台（本地测试）
--mock                                 启用模拟平台服务器
-mock-addr ADDR:PORT                   模拟服务器地址 (默认: 127.0.0.1:8000)
-mock-dir PATH                         模拟挑战目录 (默认: ./mock-challenges)
```

## 集成

### MCP 客户端

添加到您的 MCP 客户端配置中：

```json
{
  "mcpServers": {
    "ezmcp": {
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```


## 本地存储

- `.challenge_history/{challenge_code}/` - 尝试元数据、笔记和历史记录
- `.kail-history/` - 命令执行记录

## TODO

- 自动编译并启动 XBOW 靶场并配置赛题信息。

## 许可

开源。详情请参见 LICENSE 文件。

## 贡献

欢迎提出 Issue 和 Pull Request。