// Package singbox: управление процессами sing-box — один процесс = один тоннель.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	binaryOnce sync.Once
	binaryPath string
	binaryErr  error
)

// EnsureBinary возвращает путь к sing-box; при отсутствии скачивает релиз.
func EnsureBinary() (string, error) {
	binaryOnce.Do(func() {
		exe := "sing-box"
		if runtime.GOOS == "windows" {
			exe = "sing-box.exe"
		}
		if abs, err := filepath.Abs(exe); err == nil {
			exe = abs
		}
		if _, err := os.Stat(exe); err == nil {
			binaryPath = exe
			return
		}
		if err := downloadLatest(exe); err != nil {
			binaryErr = fmt.Errorf("sing-box не найден (%s) и автозагрузка не удалась: %w", exe, err)
			return
		}
		binaryPath = exe
	})
	return binaryPath, binaryErr
}

type Tunnel struct {
	cmd     *exec.Cmd
	port    int
	cfgPath string
}

var cfgDirOnce sync.Once
var cfgDirPath string
var cfgDirErr error

func tempConfigDir() (string, error) {
	cfgDirOnce.Do(func() {
		cfgDirPath, cfgDirErr = os.MkdirTemp("", "vlesscheck-sb-*")
	})
	return cfgDirPath, cfgDirErr
}

// buildConfig собирает конфиг sing-box: mixed-инбаунд на порту port + outbound из uri.
func buildConfig(uri string, port int) ([]byte, error) {
	outbound, err := parseOutbound(uri)
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []map[string]any{{
			"type": "mixed", "tag": "in",
			"listen": "127.0.0.1", "listen_port": port,
		}},
		"outbounds": []map[string]any{
			outbound,
			{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "proxy"},
	}
	return json.Marshal(cfg)
}

// Start поднимает sing-box с одним outbound из uri и mixed-инбаундом на порту port.
func Start(uri string, port int, timeout time.Duration) (*Tunnel, error) {
	exe, err := EnsureBinary()
	if err != nil {
		return nil, err
	}
	cfg, err := buildConfig(uri, port)
	if err != nil {
		return nil, fmt.Errorf("конфиг: %w", err)
	}
	dir, err := tempConfigDir()
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dir, fmt.Sprintf("sb-%d.json", port))
	if err := os.WriteFile(cfgPath, cfg, 0644); err != nil {
		return nil, err
	}

	t := &Tunnel{port: port, cfgPath: cfgPath}
	t.cmd = exec.Command(exe, "run", "-c", cfgPath)
	var stderr bytes.Buffer
	t.cmd.Stderr = &stderr
	if err := t.cmd.Start(); err != nil {
		os.Remove(cfgPath)
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, derr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if derr == nil {
			conn.Close()
			return t, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Stop()
	if msg := tail(stderr.String(), 300); msg != "" {
		return nil, fmt.Errorf("sing-box не поднял порт %d за %s: %s", port, timeout, msg)
	}
	return nil, fmt.Errorf("sing-box не поднял порт %d за %s", port, timeout)
}

// Stop убивает процесс, дожидается завершения и удаляет конфиг.
func (t *Tunnel) Stop() {
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
		done := make(chan struct{})
		go func() {
			_ = t.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	if t.cfgPath != "" {
		os.Remove(t.cfgPath)
	}
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
