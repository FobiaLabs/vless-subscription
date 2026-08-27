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

// китайские названия стран в именах узлов → флаги и английские названия
var cnFlags = map[string]string{
	"英国": "🇬🇧 UK", "美国": "🇺🇸 USA", "俄罗斯": "🇷🇺 Russia", "俄罗斯联邦": "🇷🇺 Russia",
	"瑞士": "🇨🇭 Switzerland", "德国": "🇩🇪 Germany", "法国": "🇫🇷 France", "荷兰": "🇳🇱 Netherlands",
	"日本": "🇯🇵 Japan", "韩国": "🇰🇷 Korea", "新加坡": "🇸🇬 Singapore", "中国": "🇨🇳 China",
	"意大利": "🇮🇹 Italy", "西班牙": "🇪🇸 Spain", "土耳其": "🇹🇷 Turkey", "印度": "🇮🇳 India",
	"加拿大": "🇨🇦 Canada", "澳大利亚": "🇦🇺 Australia", "芬兰": "🇫🇮 Finland", "瑞典": "🇸🇪 Sweden",
	"挪威": "🇳🇴 Norway", "丹麦": "🇩🇰 Denmark", "波兰": "🇵🇱 Poland", "乌克兰": "🇺🇦 Ukraine",
	"哈萨克斯坦": "🇰🇿 Kazakhstan", "格鲁吉亚": "🇬🇪 Georgia", "阿联酋": "🇦🇪 UAE", "以色列": "🇮🇱 Israel",
	"巴西": "🇧🇷 Brazil", "墨西哥": "🇲🇽 Mexico", "香港": "🇭🇰 Hong Kong", "台湾": "🇹🇼 Taiwan",
	"未知": "",
}

// вычистить имена генераторов и прочий мусор
var junkNameRe = regexp.MustCompile(`(?i)(by\s+ebrasha|ebrasha|free[-_\s]?nodes|@[\w.-]+|speedtest)`)

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
	// имена генераторов: "By EbraSha ⌨️", "@tg", "speedtest" и т.п.
	country = junkNameRe.ReplaceAllString(country, "")
	// числовые суффиксы вида "082714102" (таймштампы китайских генераторов)
	country = regexp.MustCompile(`[\s,_]*\d{4,}\s*$`).ReplaceAllString(country, "")
	country = regexp.MustCompile(`[^\p{L}\p{N},\s\-]`).ReplaceAllString(country, " ")
	country = regexp.MustCompile(`\s+`).ReplaceAllString(country, " ")
	country = strings.Trim(country, " -·,")
	// китайское название → флаг и английское название
	for cn, repl := range cnFlags {
		if strings.Contains(country, cn) {
			if repl == "" {
				country = ""
			} else {
				parts := strings.Fields(repl)
				flag = parts[0]
				country = strings.Join(parts[1:], " ")
			}
			break
		}
	}
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
	name := fmt.Sprintf("%s Fobia · %s", flag, icon)
	if s := speedFmt(mbps); s != "" {
		name += " " + s
	}
	name += " · " + country
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

// speedFmt — "51 Mb" если скорость измерена, иначе "" (без "0 Mb" в имени).
// Медленные (<1 Mbps) показываем с десятой, чтобы не было "0 Mb".
func speedFmt(mbps float64) string {
	if mbps > 0 {
		if mbps < 10 {
			return fmt.Sprintf("%.1f Mb", mbps)
		}
		return fmt.Sprintf("%.0f Mb", mbps)
	}
	return ""
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
