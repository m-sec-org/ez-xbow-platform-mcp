package mcpserver

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

func TestRun(t *testing.T) {
	server, err := NewMcpServer(NewMcpServerOptions(
		WithMcpServerMode(SSE),
		WithMcpServerListenAddr("127.0.0.01:8080/"),
	))
	if err != nil {
		fmt.Println(err)
	}
	server.Start()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
}
