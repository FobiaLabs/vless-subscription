// vlesschecker — проверка VLESS-ключей и публикация подписки для Happ.
//
// Этапы:
//  1. Загрузка ключей из источников
//  2. Быстрый TCP-фильтр (отсекаем мёртвые порты)
//  3. Реальная проверка через sing-box: HTTP-запрос через туннель каждого ключа
//  4. Публикация: subscription.txt (base64), working_keys.txt, stats.json + git push
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tcpWorkers    = 200 // TCP-фильтр лёгкий, можно агрессивно
	verifyWorkers = 12  // sing-box процессы тяжелее
	tcpTimeout    = 5 * time.Second
	verifyTimeout = 10 * time.Second
	maxTCPFailMs  = 2500 // отсечка латентности на этапе TCP
	basePort      = 21000
	testURL       = "https://www.gstatic.com/generate_204"
)

var sources = []string{
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
	"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
	"https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/output/vless.txt",
}

type result struct {
	Key     string  `json:"key"`
	Host    string  `json:"host"`
	Port    int     `json:"port"`
	Latency int     `json:"latency_ms"` // реальная, через туннель
	TCPMs   float64 `json:"tcp_ms"`
	Mbps    float64 `json:"mbps"` // скорость загрузки через туннель
}

var tailSuffix = regexp.MustCompile(`\s+\|\s+[^|]*$`)

func fetchKeys(url string) ([]string, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var keys []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "vless://") &&
			!strings.HasPrefix(line, "vmess://") &&
			!strings.HasPrefix(line, "ss://") &&
			!strings.HasPrefix(line, "trojan://") &&
			!strings.HasPrefix(line, "hy2://") &&
			!strings.HasPrefix(line, "hysteria2://") {
			continue
		}
		line = tailSuffix.ReplaceAllString(line, "") // хвост "| 1ms" у kort0881
		if !seen[line] {
			seen[line] = true
			keys = append(keys, line)
		}
	}
	return keys, nil
}

func uriHostPort(uri string) (string, int) {
	s := uri
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if a := strings.LastIndex(s, "@"); a >= 0 {
		s = s[a+1:]
	}
	if q := strings.IndexAny(s, "?#"); q >= 0 {
		s = s[:q]
	}
	if p := strings.IndexByte(s, '/'); p >= 0 {
		s = s[:p]
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.Replace(s, "]:", ":", 1)
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, 0
	}
	port := 0
	for _, c := range s[i+1:] {
		if c < '0' || c > '9' {
			return s[:i], 0
		}
		port = port*10 + int(c-'0')
	}
	return s[:i], port
}

func tcpFilter(keys []string) []result {
	sem := make(chan struct{}, tcpWorkers)
	var mu sync.Mutex
	var out []result
	var wg sync.WaitGroup
	for _, k := range keys {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			host, port := uriHostPort(key)
			if host == "" || port == 0 {
				return
			}
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), tcpTimeout)
			ms := time.Since(start).Seconds() * 1000
			if err != nil {
				return
			}
			conn.Close()
			if ms <= maxTCPFailMs {
				mu.Lock()
				out = append(out, result{Key: key, Host: host, Port: port, TCPMs: ms})
				mu.Unlock()
			}
		}(k)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].TCPMs < out[j].TCPMs })
	return out
}

// realVerify поднимает sing-box тоннель и делает HTTP-запрос через него.
func realVerify(r result) (result, bool) {
	port := <-portPool
	defer func() { portPool <- port }()
	t, err := Start(r.Key, port, 5*time.Second)
	if err != nil {
		return r, false
	}
	defer t.Stop()

	proxy := fmt.Sprintf("127.0.0.1:%d", port)
	client := &http.Client{
		Timeout: verifyTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustURL("socks5://" + proxy)),
		},
	}
	start := time.Now()
	req, _ := http.NewRequest("GET", testURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return r, false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return r, false
	}
	r.Latency = int(time.Since(start).Milliseconds())
	return r, true
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// portPool — пул уникальных портов для одновременно живых туннелей.
// Каждый активный туннель берёт порт из пула и возвращает его обратно,
// чтобы исключить коллизии (раньше порт считался как idx%workers — разные
// ключи одновременно получали один порт, и туннели мешали друг другу).
var portPool chan int

func initPortPool(n int) {
	portPool = make(chan int, n)
	for p := basePort; p < basePort+n; p++ {
		portPool <- p
	}
}

func main() {
	fmt.Println("=== Этап 1: загрузка источников ===")
	var all []string
	for _, src := range sources {
		keys, err := fetchKeys(src)
		if err != nil {
			fmt.Printf("⚠ %s: %v\n", shortSrc(src), err)
			continue
		}
		fmt.Printf("%s: %d ключей\n", shortSrc(src), len(keys))
		all = append(all, keys...)
	}
	uniq := dedupe(all)
	fmt.Printf("Итого уникальных: %d\n\n", len(uniq))

	fmt.Println("=== Этап 2: TCP-фильтр ===")
	passed := tcpFilter(uniq)
	fmt.Printf("Прошли TCP: %d из %d\n\n", len(passed), len(uniq))

	fmt.Println("=== Этап 3: реальная проверка (sing-box) ===")
	if _, err := EnsureBinary(); err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}
	initPortPool(verifyWorkers)
	var verified []result
	var done atomic.Int64
	sem := make(chan struct{}, verifyWorkers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, r := range passed {
		wg.Add(1)
		go func(r result, idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			vr, ok := realVerify(r)
			done.Add(1)
			status := "✅"
			if ok {
				mu.Lock()
				verified = append(verified, vr)
				mu.Unlock()
			} else {
				status = "❌"
			}
			fmt.Printf("[%d/%d] %s %s:%d", done.Load(), len(passed), status, vr.Host, vr.Port)
			if ok {
				fmt.Printf(" — %d мс", vr.Latency)
			}
			fmt.Println()
		}(r, i)
	}
	wg.Wait()
	fmt.Printf("\nРеально рабочих: %d из %d (TCP-прошли) из %d (всего)\n", len(verified), len(passed), len(uniq))

	fmt.Println("\n=== Этап 3.5: замер скорости ===")
	var speedWorkers = verifyWorkers
	var done2 atomic.Int64
	sem2 := make(chan struct{}, speedWorkers)
	var wg2 sync.WaitGroup
	for i := range verified {
		wg2.Add(1)
		go func(idx int) {
			defer wg2.Done()
			sem2 <- struct{}{}
			defer func() { <-sem2 }()
			port := <-portPool
			defer func() { portPool <- port }()
			t, err := Start(verified[idx].Key, port, 5*time.Second)
			if err != nil {
				done2.Add(1)
				return
			}
			verified[idx].Mbps = measureSpeed(verified[idx], port)
			t.Stop()
			d := done2.Add(1)
			if verified[idx].Mbps > 0 {
				fmt.Printf("[speed %d/%d] ✅ %s:%d — %.1f Mbps\n", d, len(verified), verified[idx].Host, verified[idx].Port, verified[idx].Mbps)
			} else {
				fmt.Printf("[speed %d/%d] ⚠ %s:%d — не измерена\n", d, len(verified), verified[idx].Host, verified[idx].Port)
			}
		}(i)
	}
	wg2.Wait()

	// сортировка основной подписки: по скорости, без скорости — по латентности
	sort.SliceStable(verified, func(i, j int) bool {
		if (verified[i].Mbps > 0) != (verified[j].Mbps > 0) {
			return verified[i].Mbps > 0
		}
		if verified[i].Mbps > 0 {
			return verified[i].Mbps > verified[j].Mbps
		}
		return verified[i].Latency < verified[j].Latency
	})

	fmt.Println("\n=== Этап 4: публикация ===")
	publish(verified, len(uniq))
}

// buildTop20 — топ конфигов с переименованными узлами.
// Сначала пытаемся взять по скорости (Mbps>0); если измерена хотя бы у части —
// берём их, отсортированных по скорости. Если скорость не измерилась ни у
// кого (частый случай для слабых публичных узлов) — fallback на латентность.
func buildTop20(verified []result) string {
	const topN = 20
	var top []result
	var withSpeed []result
	for _, r := range verified {
		if r.Mbps > 0 {
			withSpeed = append(withSpeed, r)
		}
	}
	if len(withSpeed) > 0 {
		sort.SliceStable(withSpeed, func(i, j int) bool { return withSpeed[i].Mbps > withSpeed[j].Mbps })
		if len(withSpeed) >= topN {
			top = withSpeed[:topN]
		} else {
			// скоростных меньше 20 — добираем по латентности
			top = withSpeed
			rest := make([]result, 0, len(verified)-len(withSpeed))
			for _, r := range verified {
				if r.Mbps == 0 {
					rest = append(rest, r)
				}
			}
			sort.SliceStable(rest, func(i, j int) bool { return rest[i].Latency < rest[j].Latency })
			need := topN - len(withSpeed)
			if len(rest) > need {
				rest = rest[:need]
			}
			top = append(top, rest...)
		}
	} else {
		// fallback: по латентности (самые быстрые по отклику)
		cp := append([]result(nil), verified...)
		sort.SliceStable(cp, func(i, j int) bool { return cp[i].Latency < cp[j].Latency })
		if len(cp) > topN {
			cp = cp[:topN]
		}
		top = cp
	}
	var lines []string
	lines = append(lines,
		"#profile-title: ⚡ Fobia VPN — Top-20 Speed",
		"#profile-update-interval: 12",
		"")
	for i, r := range top {
		lines = append(lines, renameKey(r.Key, fmt.Sprintf("%02d · %s", i+1, prettyName(r.Key, r.Mbps))))
	}
	return strings.Join(lines, "\n")
}

func publish(verified []result, total int) {
	keys := make([]string, len(verified))
	for i, r := range verified {
		keys[i] = renameKey(r.Key, prettyName(r.Key, r.Mbps))
	}
	sub := base64.StdEncoding.EncodeToString([]byte(strings.Join(keys, "\n")))
	if err := os.WriteFile("subscription.txt", []byte(sub), 0644); err != nil {
		fmt.Println("❌ subscription.txt:", err)
		return
	}
	// рабочие ключи сырьём (без переименования) — для отладки и повторного замера
	raw := make([]string, len(verified))
	for i, r := range verified {
		raw[i] = r.Key
	}
	os.WriteFile("working_keys.txt", []byte(strings.Join(raw, "\n")+"\n"), 0644)

	stats := map[string]any{
		"updated_at":    time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		"total":         total,
		"total_working": len(verified),
	}
	b, _ := json.MarshalIndent(stats, "", "  ")
	os.WriteFile("stats.json", b, 0644)

	// топ-20 по скорости с красивыми именами — отдельная подписка
	top := base64.StdEncoding.EncodeToString([]byte(buildTop20(verified)))
	if err := os.WriteFile("top20_subscription.txt", []byte(top), 0644); err != nil {
		fmt.Println("❌ top20_subscription.txt:", err)
	}

	run("git", "add", "-A")
	if code := run("git", "diff", "--cached", "--quiet"); code == 0 {
		fmt.Println("Изменений нет.")
		return
	}
	msg := fmt.Sprintf("chore: update subscription (%s) [skip ci]", stats["updated_at"])
	run("git", "commit", "-m", msg)
	run("git", "pull", "--rebase", "origin", "main")
	if code := run("git", "push", "origin", "main"); code == 0 {
		fmt.Println("✅ Опубликовано:", len(verified), "ключей")
	} else {
		fmt.Println("⚠ push не удался с первого раза, повтор...")
		time.Sleep(3 * time.Second)
		run("git", "pull", "--rebase", "origin", "main")
		if code := run("git", "push", "origin", "main"); code == 0 {
			fmt.Println("✅ Опубликовано со второй попытки")
		} else {
			fmt.Println("❌ push не удался")
		}
	}
}

func run(name string, args ...string) int {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return code
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func shortSrc(u string) string {
	parts := strings.Split(u, "/")
	if len(parts) >= 5 {
		return parts[3] + "/" + parts[4]
	}
	return u
}
