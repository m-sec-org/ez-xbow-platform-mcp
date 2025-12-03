package main

import (
	"flag"
	"fmt"
	"log/slog"
	"tencent-xbow-mcp/mcpserver"
)

var mode string
var listenAddr string
var xbowUrl string
var xbowToken string
var dockerContainer string
var dockerfileDir string
var dockerImage string
var dockerLogDir string
var mockEnable bool
var mockAddr string
var mockDir string

func init() {
	flag.StringVar(&mode, "mode", "streamable", "MCP server mode: stdio, sse, streamable")
	flag.StringVar(&mode, "m", "streamable", "MCP server mode: stdio, sse, streamable (shorthand)")

	flag.StringVar(&listenAddr, "listen", "127.0.0.1:8080", "Listen address for MCP server")
	flag.StringVar(&listenAddr, "l", "127.0.0.1:8080", "Listen address for MCP server (shorthand)")

	flag.StringVar(&xbowUrl, "xbow-url", "", "XBow URL")
	flag.StringVar(&xbowUrl, "u", "", "XBow URL (shorthand)")

	flag.StringVar(&xbowToken, "xbow-token", "", "XBow API token")
	flag.StringVar(&xbowToken, "t", "", "XBow API token (shorthand)")

	flag.StringVar(&dockerContainer, "docker-container", "xbow-kail", "Docker exec container fixed name")
	flag.StringVar(&dockerContainer, "c", "xbow-kail", "Docker exec container fixed name (shorthand)")

	flag.StringVar(&dockerLogDir, "docker-exec-log-dir", "./.kail-history", "Docker exec log directory")
	flag.StringVar(&dockerLogDir, "d", "./.kail-history", "Docker exec log directory (shorthand)")

	flag.StringVar(&dockerfileDir, "dockerfile-dir", "./Dockerfile", "Dockerfile directory")
	flag.StringVar(&dockerfileDir, "f", "./Dockerfile", "Dockerfile directory (shorthand)")

	flag.StringVar(&dockerImage, "docker-image", "xbow-kail:latest", "Docker image name:tag")
	flag.StringVar(&dockerImage, "i", "xbow-kail:latest", "Docker image name:tag (shorthand)")

	// Mock platform options
	flag.BoolVar(&mockEnable, "mock", false, "Enable local mock platform server")
	flag.StringVar(&mockAddr, "mock-addr", "127.0.0.1:8000", "Mock platform listen address")
	flag.StringVar(&mockDir, "mock-dir", "./mock-challenges", "Directory path for per-challenge JSON files")

	flag.Parse()
}

func main() {
	// Optionally start mock platform server
	if mockEnable {
		if mockDir == "" {
			mockDir = "./mock-challenges"
		}
		_, err := mcpserver.StartMockPlatformFromDir(mockAddr, xbowToken, mockDir)
		if err != nil {
			slog.Error("failed to start mock platform:", "error", err)
		} else {
			if xbowUrl == "" {
				xbowUrl = "http://" + mockAddr
			}
			slog.Info("mock platform started at", "addr", "http://"+mockAddr, "dir", mockDir)
		}
	}

	server, err := mcpserver.NewMcpServer(mcpserver.NewMcpServerOptions(
		mcpserver.WithMcpServerMode(func() mcpserver.McpMode {
			switch mode {
			case "stdio":
				return mcpserver.Stdio
			case "sse":
				return mcpserver.SSE
			case "streamable":
				return mcpserver.Streamable
			default:
				return mcpserver.Streamable
			}
		}()),
		mcpserver.WithMcpServerListenAddr(listenAddr),
		mcpserver.WithXbowUrl(xbowUrl),
		mcpserver.WithXbowToken(xbowToken),
		mcpserver.WithDockerContainer(dockerContainer),
		mcpserver.WithDockerfileDir(dockerfileDir),
		mcpserver.WithDockerImage(dockerImage),
		mcpserver.WithDockerExecLogDir(dockerLogDir),
	))
	if err != nil {
		fmt.Println(err)
	}
	server.Start()
}
