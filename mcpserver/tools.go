package mcpserver

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed ctf-skills/*.md
var ctfSkillFS embed.FS

// listChallenges implements GET /api/v1/challenges
func (s *McpServer) listChallenges(ctx context.Context, _ *mcp.CallToolRequest, _ ListChallengesInput) (*mcp.CallToolResult, ListChallengesOutput, error) {
	var out ListChallengesOutput
	if err := s.doJSON(ctx, http.MethodGet, "/api/v1/challenges", nil, &out); err != nil {
		return nil, ListChallengesOutput{}, err
	}
	noSolvedChallenges := make([]Challenge, 0)
	for _, challenge := range out.Challenges {
		code := strings.TrimSpace(challenge.ChallengeCode)
		if code == "" {
			continue
		}
		if challenge.Solved {
			continue // 已经解决的题目跳过
		}
		doing, attempts := s.readChallengeMeta(code)
		challenge.AttemptCount = attempts
		challenge.Doing = doing && !challenge.Solved

		noSolvedChallenges = append(noSolvedChallenges, challenge)
	}
	out.Challenges = noSolvedChallenges
	return nil, out, nil
}

// getHint implements GET /api/v1/hint/{challenge_code}
func (s *McpServer) getHint(ctx context.Context, _ *mcp.CallToolRequest, in GetHintInput) (*mcp.CallToolResult, GetHintOutput, error) {
	if strings.TrimSpace(in.ChallengeCode) == "" {
		return nil, GetHintOutput{}, errors.New("challenge_code is required")
	}
	var out GetHintOutput
	path := "/api/v1/hint/" + in.ChallengeCode
	if err := s.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, GetHintOutput{}, err
	}
	return nil, out, nil
}

// submitAnswer implements POST /api/v1/answer
func (s *McpServer) submitAnswer(ctx context.Context, _ *mcp.CallToolRequest, in SubmitAnswerInput) (*mcp.CallToolResult, SubmitAnswerOutput, error) {
	if strings.TrimSpace(in.ChallengeCode) == "" || strings.TrimSpace(in.Answer) == "" {
		return nil, SubmitAnswerOutput{}, errors.New("challenge_code and answer are required")
	}
	body := map[string]any{
		"challenge_code": in.ChallengeCode,
		"answer":         in.Answer,
	}
	var out SubmitAnswerOutput
	if err := s.doJSON(ctx, http.MethodPost, "/api/v1/answer", body, &out); err != nil {
		return nil, SubmitAnswerOutput{}, err
	}
	return nil, out, nil
}

// doChallenge marks a challenge as being attempted, increments attempt count, and writes local metadata/history.
func (s *McpServer) doChallenge(ctx context.Context, req *mcp.CallToolRequest, in DoChallengeInput) (*mcp.CallToolResult, DoChallengeOutput, error) {
	code := strings.TrimSpace(in.ChallengeCode)
	if code == "" {
		return nil, DoChallengeOutput{}, errors.New("challenge_code is required")
	}
	dir := s.challengeDir(code)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, DoChallengeOutput{}, fmt.Errorf("ensure history dir: %w", err)
	}
	meta := s.loadChallengeMeta(code)
	meta.Attempts++
	meta.Doing = true
	meta.UpdatedAt = time.Now().UnixMilli()

	// 每 9 轮清空一次笔记（在第 9, 18, 27... 次尝试时）
	if meta.Attempts%9 == 0 && meta.Attempts > 0 {
		notesPath := filepath.Join(dir, "notes.jsonl")
		// 删除旧的笔记文件，不写入提示
		_ = os.Remove(notesPath)
	}

	if err := s.saveChallengeMeta(code, meta); err != nil {
		return nil, DoChallengeOutput{}, err
	}
	// append attempt entry
	attemptEntry := struct {
		TimestampMs int64  `json:"timestamp_ms"`
		SessionID   string `json:"session_id"`
		Action      string `json:"action"`
	}{
		TimestampMs: time.Now().UnixMilli(),
		SessionID:   strings.TrimSpace(req.GetSession().ID()),
		Action:      "start",
	}
	if err := s.appendJSONL(filepath.Join(dir, "attempts.jsonl"), attemptEntry); err != nil {
		// non-fatal
	}
	return nil, DoChallengeOutput{Ok: true}, nil
}

// writeChallengeNote appends a note to the challenge notes file.
func (s *McpServer) writeChallengeNote(ctx context.Context, req *mcp.CallToolRequest, in WriteChallengeNoteInput) (*mcp.CallToolResult, WriteChallengeNoteOutput, error) {
	code := strings.TrimSpace(in.ChallengeCode)
	note := strings.TrimSpace(in.Note)
	if code == "" || note == "" {
		return nil, WriteChallengeNoteOutput{}, errors.New("challenge_code and note are required")
	}
	dir := s.challengeDir(code)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, WriteChallengeNoteOutput{}, fmt.Errorf("ensure history dir: %w", err)
	}

	notesPath := filepath.Join(dir, "notes.jsonl")
	entry := ChallengeNote{
		TimestampMs: time.Now().UnixMilli(),
		SessionID:   strings.TrimSpace(req.GetSession().ID()),
		Note:        note,
	}
	if err := s.appendJSONL(notesPath, entry); err != nil {
		return nil, WriteChallengeNoteOutput{}, fmt.Errorf("append note: %w", err)
	}
	// update meta timestamp (optional)
	meta := s.loadChallengeMeta(code)
	meta.UpdatedAt = time.Now().UnixMilli()
	_ = s.saveChallengeMeta(code, meta)
	return nil, WriteChallengeNoteOutput{Ok: true}, nil
}

// readChallengeNote returns all note entries for a challenge (if any).
func (s *McpServer) readChallengeNote(_ context.Context, req *mcp.CallToolRequest, in ReadChallengeNoteInput) (*mcp.CallToolResult, ReadChallengeNoteOutput, error) {
	code := strings.TrimSpace(in.ChallengeCode)
	if code == "" {
		return nil, ReadChallengeNoteOutput{}, errors.New("challenge_code is required")
	}
	dir := s.challengeDir(code)
	path := filepath.Join(dir, "notes.jsonl")

	// 每 9 轮清空一次笔记（在第 9, 18, 27... 次尝试时）
	meta := s.loadChallengeMeta(code)
	if meta.Attempts%9 == 0 && meta.Attempts > 0 {
		// 先尝试读取笔记，如果文件存在且有内容，说明已经清空并写入了新笔记
		notes, err := s.readNotesJSONL(path)
		if err == nil && len(notes) > 0 {
			// 文件存在且有新笔记，正常返回
			return nil, ReadChallengeNoteOutput{Notes: notes}, nil
		}
		// 文件不存在或为空，删除文件并返回提示
		_ = os.Remove(path)
		resetNote := ChallengeNote{
			TimestampMs: time.Now().UnixMilli(),
			SessionID:   strings.TrimSpace(req.GetSession().ID()),
			Note:        "已尝试多轮，为了防止错误积累，这道题笔记已清空。读到这条笔记的请直接获取提示进行解题。",
		}
		return nil, ReadChallengeNoteOutput{Notes: []ChallengeNote{resetNote}}, nil
	}

	notes, err := s.readNotesJSONL(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ReadChallengeNoteOutput{Notes: []ChallengeNote{}}, nil
		}
		return nil, ReadChallengeNoteOutput{}, err
	}
	return nil, ReadChallengeNoteOutput{Notes: notes}, nil
}

// kailTerminal executes a command inside a disposable Docker container and returns stdout/stderr/exit code
func (s *McpServer) kailTerminal(ctx context.Context, req *mcp.CallToolRequest, in DockerRunInput) (*mcp.CallToolResult, DockerRunOutput, error) {
	// Basic validation
	if strings.TrimSpace(in.Command) == "" {
		return nil, DockerRunOutput{}, errors.New("command is required")
	}

	// Choose container name: persistent Kail container
	{
		container := strings.TrimSpace(s.options.DockerContainer)
		if container == "" {
			container = "xbow-kail"
		}
		if in.Background {
			callID := fmt.Sprintf("%d", time.Now().UnixNano())
			started := time.Now()
			// initial running record
			initialOut := DockerRunOutput{ID: callID, Running: true}
			if err := s.persistDockerRecord(container, in.Command, initialOut, started, time.Time{}, "running", true); err != nil {
				return nil, DockerRunOutput{}, fmt.Errorf("persist initial record: %w", err)
			}
			go func() {
				// background timeout: 10 minutes
				timeout := 600
				args := []string{"exec", "-i", container, "sh", "-lc", in.Command}
				tctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
				defer cancel()
				cmd := exec.CommandContext(tctx, "docker", args...)
				var stdoutBuf, stderrBuf bytes.Buffer
				cmd.Stdout = &stdoutBuf
				cmd.Stderr = &stderrBuf
				runStart := time.Now()
				runErr := cmd.Run()
				duration := time.Since(runStart)
				stdout := stdoutBuf.String()
				out := DockerRunOutput{ID: callID, Stdout: stdout, Stderr: stderrBuf.String(), DurationMs: duration.Milliseconds()}
				if tctx.Err() == context.DeadlineExceeded {
					out.TimedOut = true
				}
				if runErr != nil {
					var exitErr *exec.ExitError
					if errors.As(runErr, &exitErr) {
						out.ExitCode = exitErr.ExitCode()
					} else {
						out.ExitCode = -1
					}
				} else {
					out.ExitCode = 0
				}
				out.Running = false
				_ = s.persistDockerRecord(container, in.Command, out, started, runStart.Add(duration), "finished", true)
			}()
			return nil, initialOut, nil
		}
		// Foreground sync
		timeout := 120
		args := []string{"exec", "-i", container, "sh", "-lc", in.Command}
		tctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
		cmd := exec.CommandContext(tctx, "docker", args...)
		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
		start := time.Now()
		runErr := cmd.Run()
		duration := time.Since(start)
		callID := fmt.Sprintf("%d", time.Now().UnixNano())
		stdout := stdoutBuf.String()
		out := DockerRunOutput{Stdout: stdout, Stderr: stderrBuf.String(), DurationMs: duration.Milliseconds(), ID: callID}
		if tctx.Err() == context.DeadlineExceeded {
			out.TimedOut = true
		}
		if runErr != nil {
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				out.ExitCode = exitErr.ExitCode()
			} else {
				out.ExitCode = -1
			}
			_ = s.persistDockerRecord(container, in.Command, out, start, start.Add(duration), "finished", false)
			return nil, out, nil
		}
		out.ExitCode = 0
		_ = s.persistDockerRecord(container, in.Command, out, start, start.Add(duration), "finished", false)
		return nil, out, nil
	}
	// Unreachable: all branches above return
}

// persistDockerRecord writes the execution record to a file named by session+callid
func (s *McpServer) persistDockerRecord(container, command string, out DockerRunOutput, started time.Time, ended time.Time, status string, background bool) error {
	if err := os.MkdirAll(s.options.DockerExecLogDir, 0o755); err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.json", out.ID)
	path := filepath.Join(s.options.DockerExecLogDir, filename)
	var endedMs int64
	if ended.IsZero() {
		endedMs = 0
	} else {
		endedMs = ended.UnixMilli()
	}
	rec := DockerRunRecord{
		ID: out.ID, Container: container, Command: command,
		Status: status, Background: background,
		ExitCode: out.ExitCode, Stdout: out.Stdout, Stderr: out.Stderr, DurationMs: out.DurationMs, TimedOut: out.TimedOut,
		StartedAt: started.UnixMilli(), EndedAt: endedMs,
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// kailGetHistory returns a previously stored command result by id, scoped to the current session
func (s *McpServer) kailGetHistory(ctx context.Context, req *mcp.CallToolRequest, in DockerHistoryGetInput) (*mcp.CallToolResult, DockerHistoryGetOutput, error) {
	if strings.TrimSpace(in.ID) == "" {
		return nil, DockerHistoryGetOutput{}, errors.New("id is required")
	}
	filename := fmt.Sprintf("%s.json", in.ID)
	path := filepath.Join(s.options.DockerExecLogDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Not found is not an error, it's a status.
			return nil, DockerHistoryGetOutput{
				Record: DockerRunRecord{
					ID:     in.ID,
					Status: "not_found",
				},
			}, nil
		}
		return nil, DockerHistoryGetOutput{}, fmt.Errorf("read history: %w", err)
	}
	var rec DockerRunRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, DockerHistoryGetOutput{}, fmt.Errorf("decode history: %w", err)
	}
	return nil, DockerHistoryGetOutput{Record: rec}, nil
}

// getCTFSkill retrieves CTF skill documentation by category name
func (s *McpServer) getCTFSkill(ctx context.Context, _ *mcp.CallToolRequest, in GetCTFSkillInput) (*mcp.CallToolResult, GetCTFSkillOutput, error) {
	category := strings.TrimSpace(strings.ToLower(in.Category))
	if category == "" {
		return nil, GetCTFSkillOutput{}, errors.New("category 参数不能为空")
	}

	// 构建文件名（支持 .md 扩展名）
	filename := category + ".md"
	filePath := "ctf-skills/" + filename

	// 尝试从嵌入的文件系统读取文件
	content, err := fs.ReadFile(ctfSkillFS, filePath)
	if err != nil {
		// 文件不存在
		if errors.Is(err, fs.ErrNotExist) {
			return nil, GetCTFSkillOutput{
				Category: category,
				Content:  "",
				Found:    false,
			}, nil
		}
		// 其他读取错误
		return nil, GetCTFSkillOutput{}, fmt.Errorf("读取技能文档失败: %w", err)
	}

	return nil, GetCTFSkillOutput{
		Category: category,
		Content:  string(content),
		Found:    true,
	}, nil
}
