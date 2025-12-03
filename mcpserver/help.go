package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type challengeMeta struct {
	Attempts  int   `json:"attempts"`
	Doing     bool  `json:"doing"`
	UpdatedAt int64 `json:"updated_at_unix_ms"`
}

func (s *McpServer) challengeDir(code string) string {
	base := strings.TrimSpace(s.options.ChallengeHistoryDir)
	if base == "" {
		base = "./.challenge_history"
	}
	return filepath.Join(base, code)
}

func (s *McpServer) loadChallengeMeta(code string) challengeMeta {
	dir := s.challengeDir(code)
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return challengeMeta{}
	}
	var m challengeMeta
	if json.Unmarshal(data, &m) != nil {
		return challengeMeta{}
	}
	return m
}

func (s *McpServer) saveChallengeMeta(code string, m challengeMeta) error {
	dir := s.challengeDir(code)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "meta.json"), data, 0o644)
}

func (s *McpServer) readChallengeMeta(code string) (bool, int) {
	m := s.loadChallengeMeta(code)
	return m.Doing, m.Attempts
}

func (s *McpServer) appendJSONL(path string, v any) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

func (s *McpServer) readNotesJSONL(path string) ([]ChallengeNote, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var notes []ChallengeNote
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var n ChallengeNote
		if err := json.Unmarshal([]byte(line), &n); err == nil {
			notes = append(notes, n)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return notes, nil
}

// doJSON composes URL = baseURL + path and performs an HTTP request with JSON body (if provided), then decodes JSON response.
func (s *McpServer) doJSON(ctx context.Context, method string, path string, body any, out any) error {
	url := strings.TrimRight(s.options.XbowUrl, "/") + path

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		bodyReader = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.options.XbowToken)
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Try to extract {"detail": "..."}
		var derr struct {
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(data, &derr); err == nil && derr.Detail != "" {
			return fmt.Errorf("%s: %s", resp.Status, derr.Detail)
		}
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// ---- Mock API (for local testing of the platform) ----

type mockChallenge struct {
	Challenge
	HintContent string
	Solution    string
}

type mockAPI struct {
	mu           sync.Mutex
	token        string
	currentStage string
	hintPenalty  int
	challenges   map[string]*mockChallenge
}

// StartMockPlatformFromDir loads all challenges from a directory of JSON files (one file per challenge)
// and starts the mock HTTP server with those challenges.
func StartMockPlatformFromDir(addr string, token string, dir string) (*http.Server, error) {
	store := &mockAPI{
		token:        strings.TrimSpace(token),
		currentStage: "debug",
		hintPenalty:  10,
		challenges:   map[string]*mockChallenge{},
	}
	type challengeFile struct {
		ChallengeCode string     `json:"challenge_code"`
		Difficulty    string     `json:"difficulty"`
		Points        int        `json:"points"`
		TargetInfo    TargetInfo `json:"target_info"`
		HintViewed    bool       `json:"hint_viewed"`
		Solved        bool       `json:"solved"`
		HintContent   string     `json:"hint_content"`
		Solution      string     `json:"solution"`
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(ent.Name()), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			return nil, err
		}
		var cf challengeFile
		if err := json.Unmarshal(data, &cf); err != nil {
			return nil, fmt.Errorf("parse %s: %w", ent.Name(), err)
		}
		if strings.TrimSpace(cf.ChallengeCode) == "" {
			return nil, fmt.Errorf("file %s missing challenge_code", ent.Name())
		}
		store.challenges[cf.ChallengeCode] = &mockChallenge{
			Challenge: Challenge{
				ChallengeCode: cf.ChallengeCode,
				Difficulty:    cf.Difficulty,
				Points:        cf.Points,
				HintViewed:    cf.HintViewed,
				Solved:        cf.Solved,
				TargetInfo:    cf.TargetInfo,
			},
			HintContent: cf.HintContent,
			Solution:    cf.Solution,
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/challenges", store.handleListChallenges)
	mux.HandleFunc("/api/v1/hint/", store.handleGetHint)
	mux.HandleFunc("/api/v1/answer", store.handleSubmitAnswer)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	go func() { _ = srv.ListenAndServe() }()
	return srv, nil
}

func (m *mockAPI) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if m.token == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	want := "Bearer " + m.token
	if auth != want {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "unauthorized"})
		return false
	}
	return true
}

func (m *mockAPI) handleListChallenges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"detail": "method not allowed"})
		return
	}
	if !m.checkAuth(w, r) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var list []Challenge
	for _, ch := range m.challenges {
		list = append(list, ch.Challenge)
	}
	out := ListChallengesOutput{
		CurrentStage: m.currentStage,
		Challenges:   list,
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *mockAPI) handleGetHint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"detail": "method not allowed"})
		return
	}
	if !m.checkAuth(w, r) {
		return
	}
	code := strings.TrimPrefix(r.URL.Path, "/api/v1/hint/")
	code = strings.TrimSpace(code)
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "challenge_code required"})
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.challenges[code]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "challenge not found"})
		return
	}
	first := !ch.HintViewed
	ch.HintViewed = true
	// mirror into embedded Challenge
	ch.Challenge.HintViewed = true
	writeJSON(w, http.StatusOK, GetHintOutput{
		HintContent:   ch.HintContent,
		PenaltyPoints: m.hintPenalty,
		FirstUse:      first,
	})
}

func (m *mockAPI) handleSubmitAnswer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"detail": "method not allowed"})
		return
	}
	if !m.checkAuth(w, r) {
		return
	}
	var in SubmitAnswerInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "invalid json"})
		return
	}
	code := strings.TrimSpace(in.ChallengeCode)
	ans := strings.TrimSpace(in.Answer)
	if code == "" || ans == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "challenge_code and answer required"})
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.challenges[code]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "challenge not found"})
		return
	}
	correct := ans == ch.Solution
	if !correct {
		writeJSON(w, http.StatusOK, SubmitAnswerOutput{
			Correct:      false,
			EarnedPoints: 0,
			IsSolved:     ch.Solved,
		})
		return
	}
	// correct
	if ch.Solved {
		writeJSON(w, http.StatusOK, SubmitAnswerOutput{
			Correct:      true,
			EarnedPoints: 0,
			IsSolved:     true,
		})
		return
	}
	earned := ch.Points
	if ch.HintViewed && m.hintPenalty > 0 {
		if earned > m.hintPenalty {
			earned -= m.hintPenalty
		} else {
			earned = 0
		}
	}
	ch.Solved = true
	ch.Challenge.Solved = true
	writeJSON(w, http.StatusOK, SubmitAnswerOutput{
		Correct:      true,
		EarnedPoints: earned,
		IsSolved:     false,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
