// speed.go — замер скорости через поднятый туннель + красивые имена узлов.
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	dlTestBytes = 2 << 20 // 2 MB на конфиг
	dlTimeout   = 20 * time.Second
	speedURL    = "https://speed.cloudflare.com/__down?bytes="
)

var emojiRe = regexp.MustCompile(`[\x{1F1E6}-\x{1F1FF}]{2}`)
var junkRe = regexp.MustCompile(`[\x{1F300}-\x{1FAFF}\x{2B00}-\x{2BFF}✅⭐🔥❄️⚡]`)

// measureSpeed качает dlTestBytes через туннель, возвращает Mbps (0 — не удалось).
func measureSpeed(r result, port int) float64 {
	pu := mustURL(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	client := &http.Client{
		Timeout:   dlTimeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}
	start := time.Now()
	resp, err := client.Get(speedURL + fmt.Sprint(dlTestBytes))
	if err != nil {
		return 0
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	el := time.Since(start).Seconds()
	if n < 1000 || el <= 0 {
		return 0
	}
	return float64(n) * 8 / el / 1e6
}

// prettyName строит имя вида "🇩🇪 Fobia · 🚀 44 Mb · Germany".
// Пинг не включаем — Happ показывает свой.
func prettyName(key string, mbps float64) string {
	frag := ""
	if i := strings.Index(key, "#"); i >= 0 {
		frag = key[i+1:]
	}
	// фрагмент в ключах обычно процентно-закодирован — раскодируем
	if dec, err := url.QueryUnescape(frag); err == nil {
		frag = dec
	}
	flag := "🌐"
	if m := emojiRe.FindString(frag); m != "" {
		flag = m
	}
	country := junkRe.ReplaceAllString(frag, "")
	country = strings.ReplaceAll(country, "|", " ")
	country = regexp.MustCompile(`\[BL\]|\[WL\]`).ReplaceAllString(country, "")
	// убрать повторные флаги и мусорные токены
	country = emojiRe.ReplaceAllString(country, "")
	country = regexp.MustCompile(`(?i)\b(anycast-ip|anycast|unknown|free-nodes|vless-\d+)\b`).ReplaceAllString(country, "")
	country = regexp.MustCompile(`[^\p{L}\p{N},\s\-]`).ReplaceAllString(country, " ")
	country = regexp.MustCompile(`\s+`).ReplaceAllString(country, " ")
	country = strings.Trim(country, " -·,")
	// первая буква в верхний регистр без внешних зависимостей
	if country != "" {
		r := []rune(country)
		if r[0] >= 'a' && r[0] <= 'z' {
			r[0] = r[0] - 32
			country = string(r)
		}
	}
	if country == "" || len([]rune(country)) > 24 {
		country = hostOnly(key)
	}
	icon := "✔"
	switch {
	case mbps >= 40:
		icon = "🚀"
	case mbps >= 25:
		icon = "⚡"
	case mbps >= 10:
		icon = "✅"
	case mbps > 0:
		icon = "🐌"
	}
	name := fmt.Sprintf("%s Fobia · %s %.0f Mb · %s", flag, icon, mbps, country)
	const maxLen = 60
	runeName := []rune(name)
	if len(runeName) > maxLen {
		name = string(runeName[:maxLen])
		// не оставляем оборванные эмодзи/суррогаты на границе
		for len(name) > 0 && (strings.HasSuffix(name, string(rune(0xFFFD))) || !utf8.ValidString(name)) {
			r := []rune(name)
			name = string(r[:len(r)-1])
		}
		name += "…"
	}
	return name
}

// hostOnly — хост без порта, для случаев когда имя страны слишком длинное.
func hostOnly(uri string) string {
	h := hostOf(uri)
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i+1:], ".") {
		h = h[:i] // срезаем порт у ip:port
	}
	return h
}

// renameKey заменяет фрагмент-имя ключа.
func renameKey(key, name string) string {
	base := key
	if i := strings.Index(base, "#"); i >= 0 {
		base = base[:i]
	}
	return base + "#" + strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
}

func hostOf(uri string) string {
	s := uri
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if a := strings.LastIndex(s, "@"); a >= 0 {
		s = s[a+1:]
	}
	if q := strings.IndexAny(s, "?#/"); q >= 0 {
		s = s[:q]
	}
	return s
}
