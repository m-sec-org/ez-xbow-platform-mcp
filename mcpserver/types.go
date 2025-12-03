package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

type McpServerMode string

type McpServerOptions struct {
	Mode                McpMode
	ListenAddr          string
	Secret              string
	XbowUrl             string
	XbowToken           string
	DockerExecLogDir    string
	DockerfileDir       string
	DockerImage         string
	DockerContainer     string
	Ctx                 context.Context
	ChallengeHistoryDir string
}

type McpServerOption func(*McpServerOptions)

func NewMcpServerOptions(options ...McpServerOption) *McpServerOptions {
	opts := &McpServerOptions{
		Mode:                Streamable,
		ListenAddr:          "127.0.0.1:3000",
		Ctx:                 context.Background(),
		XbowUrl:             "http://127.0.0.1:8000",
		XbowToken:           "1234567890",
		DockerExecLogDir:    "./.kail-history",
		DockerfileDir:       "./Dockerfile",
		DockerImage:         "xbow-kail:latest",
		DockerContainer:     "xbow-kail",
		ChallengeHistoryDir: "./.challenge_history",
	}
	for _, opt := range options {
		opt(opts)
	}
	return opts
}

func WithMcpServerMode(mode McpMode) McpServerOption {
	return func(opts *McpServerOptions) {
		opts.Mode = mode
	}
}
func WithMcpServerListenAddr(addr string) McpServerOption {
	return func(opts *McpServerOptions) {
		opts.ListenAddr = addr
	}
}
func WithContext(ctx context.Context) McpServerOption {
	return func(opts *McpServerOptions) {
		opts.Ctx = ctx
	}
}
func WithXbowUrl(url string) McpServerOption {
	return func(opts *McpServerOptions) {
		opts.XbowUrl = url
	}
}
func WithXbowToken(token string) McpServerOption {
	return func(opts *McpServerOptions) {
		opts.XbowToken = token
	}
}

// WithDockerExecContainer sets a fixed container name for docker exec
// WithDockerExecLogDir sets the directory to store command execution logs
func WithDockerExecLogDir(dir string) McpServerOption {
	return func(opts *McpServerOptions) {
		opts.DockerExecLogDir = dir
	}
}

// WithDockerfileDir sets the directory containing Dockerfile for building the image
func WithDockerfileDir(dir string) McpServerOption {
	return func(opts *McpServerOptions) {
		opts.DockerfileDir = dir
	}
}

// WithDockerImage sets the docker image name:tag to use for the Kali environment
func WithDockerImage(image string) McpServerOption {
	return func(opts *McpServerOptions) {
		opts.DockerImage = image
	}
}

// WithDockerContainer sets the container name used to run the Kali environment
func WithDockerContainer(name string) McpServerOption {
	return func(opts *McpServerOptions) {
		opts.DockerContainer = name
	}
}

// WithChallengeHistoryDir sets the directory to store challenge history and notes
func WithChallengeHistoryDir(dir string) McpServerOption {
	return func(opts *McpServerOptions) {
		opts.ChallengeHistoryDir = dir
	}
}

type McpMode int

const (
	Stdio = iota
	SSE
	Streamable
)

func (s *McpMode) Set(val string) error {
	switch strings.ToLower(val) {
	case "stdio":
		*s = Stdio
	case "sse":
		*s = SSE
	case "streamable":
		*s = Streamable
	default:
		return errors.New("invalid output format: " + val)
	}
	return nil
}
func (s *McpMode) Get() any { return s }
func (s *McpMode) String() string {
	switch *s {
	case Stdio:
		return "stdio"
	case SSE:
		return "sse"
	case Streamable:
		return "streamable"
	default:
		return "unknown"
	}
}
func (p McpMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p McpMode) MarshalYAML() (interface{}, error) {
	return p.String(), nil
}

// DockerRunOutput is the result of the docker-run tool
type DockerRunOutput struct {
	ExitCode   int    `json:"exit_code" jsonschema:"进程退出码"`
	Stdout     string `json:"stdout" jsonschema:"标准输出"`
	Stderr     string `json:"stderr" jsonschema:"标准错误"`
	DurationMs int64  `json:"duration_ms" jsonschema:"执行耗时(毫秒)"`
	TimedOut   bool   `json:"timed_out" jsonschema:"是否超时终止"`
	ID         string `json:"id" jsonschema:"本次执行的唯一标识，可用 kail.get_history 查询历史记录"`
	Running    bool   `json:"running" jsonschema:"是否仍在后台运行（仅 background=true 时返回 true）"`
}

// DockerRunRecord is the persisted record format
type DockerRunRecord struct {
	ID         string `json:"id"`
	Container  string `json:"container"`
	Command    string `json:"command"`
	Status     string `json:"status"`
	Background bool   `json:"background"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs int64  `json:"duration_ms"`
	TimedOut   bool   `json:"timed_out"`
	StartedAt  int64  `json:"started_at_unix_ms"`
	EndedAt    int64  `json:"ended_at_unix_ms"`
}

// DockerHistoryGetInput for querying a historical record by id (scoped to session)
type DockerHistoryGetInput struct {
	ID string `json:"id" jsonschema:"required; 通过执行返回的 id 查询历史记录"`
}

// DockerHistoryGetOutput returns the stored record
type DockerHistoryGetOutput struct {
	Record DockerRunRecord `json:"record"`
}

// DockerRunInput defines inputs for executing a command inside a pre-started session container
type DockerRunInput struct {
	Command    string `json:"command" jsonschema:"required; 在会话容器中执行的命令，如 echo hi"`
	Background bool   `json:"background" jsonschema:"可选; true 则后台执行，立即返回 id，可用 kail.get_history 查询"`
}

// ListChallengesInput defines optional overrides for base URL and token.
type ListChallengesInput struct {
}

type TargetInfo struct {
	IP   string `json:"ip" jsonschema:"目标服务器 IP 地址"`
	Port []int  `json:"port" jsonschema:"目标服务器端口列表"`
}

type Challenge struct {
	ChallengeCode string     `json:"challenge_code" jsonschema:"赛题唯一标识码"`
	Difficulty    string     `json:"difficulty" jsonschema:"难度等级（easy/medium/hard）"`
	Points        int        `json:"points" jsonschema:"该题目的基础分值"`
	HintViewed    bool       `json:"hint_viewed" jsonschema:"是否已查看过提示"`
	Solved        bool       `json:"solved" jsonschema:"是否已成功解答"`
	TargetInfo    TargetInfo `json:"target_info" jsonschema:"目标服务器信息"`
	// Local fields (derived from .challenge_history), not provided by remote API
	AttemptCount int  `json:"attempt_count" jsonschema:"本地记录的尝试次数（通过 do_challenge 累积）"`
	Doing        bool `json:"doing" jsonschema:"是否当前正在尝试（本地标记）"`
}

type ListChallengesOutput struct {
	CurrentStage string      `json:"current_stage" jsonschema:"当前所处的阶段（debug：调试阶段，competition：正式答题阶段）"`
	Challenges   []Challenge `json:"challenges" jsonschema:"赛题列表"`
}

// GetHintInput request
type GetHintInput struct {
	ChallengeCode string `json:"challenge_code" jsonschema:"required; 赛题唯一标识码"`
}

// GetHintOutput response
type GetHintOutput struct {
	HintContent   string `json:"hint_content" jsonschema:"提示内容"`
	PenaltyPoints int    `json:"penalty_points" jsonschema:"查看提示的惩罚积分"`
	FirstUse      bool   `json:"first_use" jsonschema:"是否为首次查看"`
}

// SubmitAnswerInput request
type SubmitAnswerInput struct {
	ChallengeCode string `json:"challenge_code" jsonschema:"required; 赛题唯一标识码"`
	Answer        string `json:"answer" jsonschema:"required; 答案内容（flag 格式，如 flag{...}）"`
}

// SubmitAnswerOutput response
type SubmitAnswerOutput struct {
	Correct      bool `json:"correct" jsonschema:"答案是否正确"`
	EarnedPoints int  `json:"earned_points" jsonschema:"本次获得的积分（已扣除惩罚积分）"`
	IsSolved     bool `json:"is_solved" jsonschema:"该题目之前是否已被解答"`
}

// DoChallengeInput request: mark a challenge as being attempted and increment attempts
type DoChallengeInput struct {
	ChallengeCode string `json:"challenge_code" jsonschema:"required; 赛题唯一标识码"`
}

// DoChallengeOutput response
type DoChallengeOutput struct {
	Ok bool `json:"ok"`
}

// WriteChallengeNoteInput request: append a note entry for a challenge
type WriteChallengeNoteInput struct {
	ChallengeCode string `json:"challenge_code" jsonschema:"required; 赛题唯一标识码"`
	Note          string `json:"note" jsonschema:"required; 记录的笔记/尝试说明"`
}

// WriteChallengeNoteOutput response
type WriteChallengeNoteOutput struct {
	Ok bool `json:"ok"`
}

// ChallengeNote is a single note item
type ChallengeNote struct {
	TimestampMs int64  `json:"timestamp_ms"`
	SessionID   string `json:"session_id"`
	Note        string `json:"note"`
}

// ReadChallengeNoteInput request
type ReadChallengeNoteInput struct {
	ChallengeCode string `json:"challenge_code" jsonschema:"required; 赛题唯一标识码"`
}

// ReadChallengeNoteOutput response
type ReadChallengeNoteOutput struct {
	Notes []ChallengeNote `json:"notes"`
}

// GetCTFSkillInput defines inputs for getting CTF skill document
type GetCTFSkillInput struct {
	Category string `json:"category" jsonschema:"required; CTF 技巧类别名称（如：idor、xss、sql、ssti、ssrf、xxe、lfi、codei、afr&pt）"`
}

// GetCTFSkillOutput defines output for CTF skill document
type GetCTFSkillOutput struct {
	Category string `json:"category" jsonschema:"技能类别名称"`
	Content  string `json:"content" jsonschema:"完整的技能文档内容"`
	Found    bool   `json:"found" jsonschema:"是否找到该类别的文档"`
}
