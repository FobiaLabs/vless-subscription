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

// prettyName строит имя вида "🇩🇪 🚀 44Mb · Germany, Frankfurt".
// Пинг не включаем — Happ показывает свой.
func prettyName(key string, mbps float64) string {
	frag := ""
	if i := strings.Index(key, "#"); i >= 0 {
		frag = key[i+1:]
	}
	flag := "🌐"
	if m := emojiRe.FindString(frag); m != "" {
		flag = m
	}
	country := junkRe.ReplaceAllString(frag, "")
	country = strings.ReplaceAll(country, "|", " ")
	country = regexp.MustCompile(`\[BL\]|\[WL\]`).ReplaceAllString(country, "")
	country = regexp.MustCompile(`\s+`).ReplaceAllString(country, " ")
	country = strings.Trim(country, " -·")
	// первая буква в верхний регистр без внешних зависимостей
	if country != "" {
		r := []rune(country)
		if r[0] >= 'a' && r[0] <= 'z' {
			r[0] = r[0] - 32
			country = string(r)
		}
	}
	if country == "" {
		country = hostOf(key)
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
	name := fmt.Sprintf("%s %s %.0fMb · %s", flag, icon, mbps, country)
	const maxLen = 60
	runeName := []rune(name)
	if len(runeName) > maxLen {
		name = string(runeName[:maxLen]) + "…"
	}
	return name
}

// renameKey заменяет фрагмент-имя ключа.
func renameKey(key, name string) string {
	base := key
	if i := strings.Index(base, "#"); i >= 0 {
		base = base[:i]
	}
	return base + "#" + url.QueryEscape(name)
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
