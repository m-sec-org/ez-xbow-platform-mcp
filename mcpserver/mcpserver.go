package mcpserver

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type McpServer struct {
	options *McpServerOptions
	engine  *mcp.Server
}

func NewMcpServer(options *McpServerOptions) (*McpServer, error) {
	mcpServer := &McpServer{
		options: options,
	}
	mcpServer.initEngine()
	mcpServer.initTools()
	return mcpServer, nil
}

func (s *McpServer) initEngine() {
	s.engine = mcp.NewServer(&mcp.Implementation{
		Name:    "腾讯云黑客松-智能渗透挑战赛-本工具提供智能渗透挑战赛的完整 API 接口说明，参赛者需要使用这些 API 来获取赛题信息、查看提示以及提交 flag。",
		Version: "1.0",
	}, &mcp.ServerOptions{
		KeepAlive: 10 * time.Minute,
	})
}

func (s *McpServer) initTools() {
	mcp.AddTool(s.engine, &mcp.Tool{
		Name:        "list_challenges",
		Description: "获取当前阶段赛题列表（current_stage 与赛题明细）",
	}, s.listChallenges)
	mcp.AddTool(s.engine, &mcp.Tool{
		Name:        "get_challenge_hint",
		Description: "查看指定赛题的提示,会扣除相应分数，建议attempt_count>=2时使用",
	}, s.getHint)
	mcp.AddTool(s.engine, &mcp.Tool{
		Name:        "do_challenge",
		Description: "标记开始尝试指定赛题（本地增加尝试次数并标记正在做）",
	}, s.doChallenge)
	mcp.AddTool(s.engine, &mcp.Tool{
		Name:        "write_challenge_note",
		Description: "为指定赛题写入笔记/尝试记录，便于其他 LLM 复用经验",
	}, s.writeChallengeNote)
	mcp.AddTool(s.engine, &mcp.Tool{
		Name:        "read_challenge_note",
		Description: "读取指定赛题的历史笔记/尝试记录（来自本地 .challenge_history）",
	}, s.readChallengeNote)
	mcp.AddTool(s.engine, &mcp.Tool{
		Name:        "submit_answer",
		Description: "提交赛题答案，返回是否正确与得分",
	}, s.submitAnswer)
	mcp.AddTool(s.engine, &mcp.Tool{
		Name:        "kail_terminal",
		Description: "在持久化 Kali 容器中执行命令，返回输出与退出码；执行完成返回 id，可用 get_terminal_history 查询历史结果",
	}, s.kailTerminal)
	mcp.AddTool(s.engine, &mcp.Tool{
		Name:        "get_terminal_history",
		Description: "根据 id 查询历史命令执行结果（按会话隔离）",
	}, s.kailGetHistory)
	mcp.AddTool(s.engine, &mcp.Tool{
		Name:        "get_ctf_skill",
		Description: "获取指定类别的 CTF 技巧文档，支持的类别：idor（访问控制）、xss（跨站脚本）、sql（SQL注入）、ssti（模板注入）、ssrf（服务端请求伪造）、xxe（XML外部实体）、lfi（本地文件包含）、codei（代码注入）、afr&pt（任意文件读取和路径遍历）",
	}, s.getCTFSkill)
}

func (s *McpServer) Start() {
	// Ensure Kali container is available before serving
	if err := s.ensureKailContainer(); err != nil {
		slog.Warn("Failed to ensure Kail container", "error", err)
	}
	go func() {
		switch s.options.Mode {
		case Stdio:
			if err := s.engine.Run(s.options.Ctx, &mcp.StdioTransport{}); err != nil {
				slog.Warn("Failed to start MCP server", "error", err)
				os.Exit(0)
				return
			}
		case SSE:
			handler := mcp.NewSSEHandler(func(request *http.Request) *mcp.Server {
				return s.engine
			}, nil)
			slog.Info("MCP SSE server started", "addr", s.options.ListenAddr)
			slog.Error("Failed to start MCP server", "error", http.ListenAndServe(s.options.ListenAddr, handler))
		case Streamable:
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
				return s.engine
			}, nil)
			slog.Info("MCP Streamable server started", "addr", s.options.ListenAddr)
			slog.Error("Failed to start MCP server", "error", http.ListenAndServe(s.options.ListenAddr, handler))
		}
	}()
	//优雅停机
	ctx, stop := signal.NotifyContext(s.options.Ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	// On shutdown, remove container
	container := s.options.DockerContainer
	if container == "" {
		container = "xbow-kail"
	}
	_ = exec.Command("docker", "rm", "-f", container).Run()
}

// ensureKailContainer ensures the Kali image exists (build if missing) and a background container is running.
// The container runs in detached mode with --rm so it is auto-removed on exit.
func (s *McpServer) ensureKailContainer() error {

	// 1) Ensure image exists
	if err := exec.Command("docker", "image", "inspect", s.options.DockerContainer).Run(); err != nil {
		// Build using Dockerfile
		if s.options.DockerfileDir == "" {
			return fmt.Errorf("image %s not found and DockerfileDir is empty", s.options.DockerImage)
		}
		cmd := exec.Command("docker", "buildx", "build", "--platform=linux/amd64", "-t", s.options.DockerImage, "-f", s.options.DockerfileDir, ".")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		slog.Info("docker image built", "image", s.options.DockerImage)
	}
	// 2) Check container state
	inspect := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", s.options.DockerContainer)
	var inspOut bytes.Buffer
	inspect.Stdout = &inspOut
	inspect.Stderr = &inspOut
	if err := inspect.Run(); err == nil {
		if bytes.Contains(inspOut.Bytes(), []byte("true")) {
			// Already running
			return nil
		}
		// Exists but not running -> remove
		_ = exec.Command("docker", "rm", "-f", s.options.DockerContainer).Run()
	}
	// 3) Run container detached with --rm
	run := exec.Command("docker", "run", "-d", "--rm", "--name", s.options.DockerContainer, s.options.DockerImage, "sh", "-lc", "tail -f /dev/null")
	var runOut bytes.Buffer
	run.Stdout = &runOut
	run.Stderr = &runOut
	if err := run.Run(); err != nil {
		slog.Warn("docker run failed", "output", runOut.String(), "error", err)
		return err
	}
	slog.Info("kail container started", "container", s.options.DockerContainer, "image", s.options.DockerImage)
	return nil
}
