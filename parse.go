// Package singbox: парсинг share-URI в outbound-конфиг sing-box.
// Переиспользовано из vpnfast/internal/singbox (parse.go).
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func parseOutbound(raw string) (map[string]any, error) {
	switch {
	case strings.HasPrefix(raw, "vless://"):
		return parseVLESS(raw)
	case strings.HasPrefix(raw, "vmess://"):
		return parseVMess(raw)
	case strings.HasPrefix(raw, "ss://"):
		return parseSS(raw)
	case strings.HasPrefix(raw, "trojan://"):
		return parseTrojan(raw, "trojan")
	case strings.HasPrefix(raw, "hysteria2://"), strings.HasPrefix(raw, "hy2://"):
		return parseTrojan(strings.Replace(raw, "hy2://", "hysteria2://", 1), "hysteria2")
	default:
		return nil, fmt.Errorf("неподдерживаемый протокол: %.20s", raw)
	}
}

func parseVLESS(u string) (map[string]any, error) {
	p, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	q := p.Query()
	out := map[string]any{
		"type": "vless", "tag": "proxy",
		"server": p.Hostname(), "server_port": atoi(p.Port()),
		"uuid": p.User.Username(),
	}
	if flow := q.Get("flow"); flow != "" {
		out["flow"] = flow
	}
	insecure := isInsecure(q)
	switch q.Get("security") {
	case "reality":
		tls := map[string]any{
			"enabled":     true,
			"server_name": or(q.Get("sni"), p.Hostname()),
			"utls": map[string]any{
				"enabled":     true,
				"fingerprint": or(q.Get("fp"), "chrome"),
			},
			"reality": map[string]any{
				"enabled":    true,
				"public_key": q.Get("pbk"),
				"short_id":   q.Get("sid"),
			},
		}
		applyInsecure(tls, insecure)
		out["tls"] = tls
	case "tls":
		out["tls"] = buildTLS(q, p.Hostname(), insecure)
	}
	if tr := parseTransport(q); tr != nil {
		out["transport"] = tr
	}
	return out, nil
}

func parseVMess(u string) (map[string]any, error) {
	raw, err := b64decode(strings.TrimPrefix(u, "vmess://"))
	if err != nil {
		return nil, fmt.Errorf("vmess base64: %w", err)
	}
	var j struct {
		Add           string `json:"add"`
		Port          any    `json:"port"`
		ID            string `json:"id"`
		Aid           any    `json:"aid"`
		Net           string `json:"net"`
		Host          string `json:"host"`
		Path          string `json:"path"`
		TLS           string `json:"tls"`
		SNI           string `json:"sni"`
		AllowInsecure any    `json:"allowInsecure"`
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, err
	}
	q := url.Values{}
	if j.Net != "" {
		q.Set("type", j.Net)
	}
	if j.Path != "" {
		q.Set("path", j.Path)
	}
	if j.Host != "" {
		q.Set("host", j.Host)
	}
	if j.SNI != "" {
		q.Set("sni", j.SNI)
	}
	out := map[string]any{
		"type": "vmess", "tag": "proxy",
		"server": j.Add, "server_port": anyInt(j.Port),
		"uuid": j.ID, "security": "auto",
	}
	if aid := anyInt(j.Aid); aid > 0 {
		out["alter_id"] = aid
	}
	insecure := truthy(j.AllowInsecure)
	if insecure {
		q.Set("allowInsecure", "1")
	}
	if j.TLS == "tls" {
		out["tls"] = buildTLS(q, or(j.SNI, j.Host), insecure)
	}
	if tr := parseTransport(q); tr != nil {
		out["transport"] = tr
	}
	return out, nil
}

func parseSS(u string) (map[string]any, error) {
	u = strings.TrimPrefix(u, "ss://")
	if hash := strings.IndexByte(u, '#'); hash >= 0 {
		u = u[:hash]
	}
	query := ""
	if qm := strings.IndexByte(u, '?'); qm >= 0 {
		query = u[qm+1:]
		u = u[:qm]
	}
	at := strings.IndexByte(u, '@')
	if at < 0 { // целиком base64
		dec, err := b64decode(u)
		if err != nil {
			return nil, fmt.Errorf("ss: не удалось разобрать")
		}
		return parseSS("ss://" + string(dec))
	}
	cred := u[:at]
	if !strings.Contains(cred, ":") {
		if dec, err := b64decode(cred); err == nil {
			cred = string(dec)
		}
	}
	parts := strings.SplitN(cred, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("ss: method:pass не разобраны")
	}
	method, pass := parts[0], parts[1]
	host, port, err := splitHostPort(u[at+1:])
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"type": "shadowsocks", "tag": "proxy",
		"server": host, "server_port": port,
		"method": method, "password": pass,
	}
	if plugin := queryValues(query).Get("plugin"); plugin != "" {
		name, opts := splitPlugin(plugin)
		if name == "simple-obfs" || name == "simple-obfs-local" {
			name = "obfs-local"
		}
		if name == "obfs-local" || name == "v2ray-plugin" {
			out["plugin"] = name
			out["plugin_opts"] = opts
		}
	}
	return out, nil
}

func parseTrojan(u, protoType string) (map[string]any, error) {
	p, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	q := p.Query()
	tls := map[string]any{
		"enabled":     true,
		"server_name": or(q.Get("sni"), p.Hostname()),
	}
	if fp := q.Get("fp"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	applyInsecure(tls, isInsecure(q))
	out := map[string]any{
		"type": protoType, "tag": "proxy",
		"server": p.Hostname(), "server_port": atoi(p.Port()),
		"password": p.User.Username(),
		"tls":      tls,
	}
	if obfs := q.Get("obfs"); obfs == "salamander" {
		out["obfs"] = map[string]any{"type": "salamander", "password": q.Get("obfs-password")}
	}
	return out, nil
}

func buildTLS(q url.Values, defaultSNI string, insecure bool) map[string]any {
	tls := map[string]any{"enabled": true}
	if sni := q.Get("sni"); sni != "" {
		tls["server_name"] = sni
	} else if defaultSNI != "" && !isIP(defaultSNI) {
		tls["server_name"] = defaultSNI
	}
	if fp := q.Get("fp"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	applyInsecure(tls, insecure)
	return tls
}

func parseTransport(q url.Values) map[string]any {
	host := q.Get("host")
	path := q.Get("path")
	switch q.Get("type") {
	case "ws":
		tr := map[string]any{"type": "ws", "path": or(path, "/")}
		if host != "" {
			tr["headers"] = map[string]any{"Host": host}
		}
		if ed := q.Get("ed"); ed != "" {
			tr["max_early_data"] = atoi(ed)
			tr["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		return tr
	case "grpc":
		tr := map[string]any{"type": "grpc"}
		if sn := q.Get("serviceName"); sn != "" {
			tr["service_name"] = sn
		}
		return tr
	case "http", "h2":
		tr := map[string]any{"type": "http"}
		if host != "" {
			tr["host"] = []string{host}
		}
		if path != "" {
			tr["path"] = path
		}
		return tr
	case "httpupgrade":
		tr := map[string]any{"type": "httpupgrade", "path": or(path, "/")}
		if host != "" {
			tr["host"] = host
		}
		return tr
	default:
		return nil
	}
}

func applyInsecure(tls map[string]any, insecure bool) {
	if insecure {
		tls["insecure"] = true
	}
}

func isInsecure(q url.Values) bool {
	v := or(q.Get("allowInsecure"), q.Get("insecure"))
	return v == "1" || strings.EqualFold(v, "true")
}

func splitHostPort(s string) (string, int, error) {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if strings.HasPrefix(s, "[") {
		j := strings.IndexByte(s, ']')
		if j < 0 {
			return "", 0, fmt.Errorf("ss: незакрытая скобка ipv6")
		}
		rest := s[j+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("ss: нет порта")
		}
		return s[1:j], atoi(rest[1:]), nil
	}
	lastColon := strings.LastIndexByte(s, ':')
	if lastColon < 0 {
		return "", 0, fmt.Errorf("ss: нет порта")
	}
	return s[:lastColon], atoi(s[lastColon+1:]), nil
}

func splitPlugin(p string) (string, string) {
	parts := strings.SplitN(p, ";", 2)
	opts := ""
	if len(parts) == 2 {
		opts = parts[1]
	}
	return parts[0], opts
}

func queryValues(raw string) url.Values {
	v, _ := url.ParseQuery(raw)
	return v
}

func b64decode(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding,
	} {
		if dec, err := enc.DecodeString(s); err == nil {
			return dec, nil
		}
	}
	return nil, fmt.Errorf("base64 decode failed")
}

func anyInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		return atoi(n)
	case bool:
		if n {
			return 1
		}
	}
	return 0
}

func truthy(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "1" || strings.EqualFold(b, "true")
	case float64:
		return b != 0
	}
	return false
}

func isIP(s string) bool { return net.ParseIP(s) != nil }

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
