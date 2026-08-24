#!/usr/bin/env python3
"""Проверяет VLESS-ключи локально и публикует подписку для Happ.

1. Загружает ключи из источника (igareck/vpn-configs-for-russia)
2. Проверяет TCP-доступность каждого сервера с этого устройства
3. Рабочие ключи пишет в subscription.txt (base64-подписка) + raw список
4. Коммитит и пушит в GitHub — Happ забирает по raw-ссылке
"""
import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import requests

REPO_DIR = Path(__file__).parent
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    # 0xRadikal/Free-v2ray-Configs — общий список (vless/vmess/trojan/hy2), берём только vless://
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    # kort0881/vpn-vless-configs-russia — vless с суффиксом "| 1ms" в конце строк
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/output/vless.txt",
]
MAX_WORKERS = 80
TEST_TIMEOUT = 5
MAX_LATENCY_MS = 2500

COUNTRIES = {
    "baltics": ["lithuania", "estonia", "latvia"],
    "finland": ["finland"],
    "germany": ["germany"],
    "sweden": ["sweden"],
    "netherlands": ["netherlands"],
    "poland": ["poland"],
}
ALL_KEYWORDS = [kw for kws in COUNTRIES.values() for kw in kws]


def fetch_keys(url):
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    keys = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line.startswith("vless://"):
            continue
        # kort0881 пишет "vless://... | 1ms" — обрезаем хвост после первого " | "
        if " | " in line.split("#", 1)[-1] or line.rstrip().rfind(" | ") > line.rfind("#"):
            line = line[: line.rfind(" | ")].strip()
        keys.append(line)
    return list(dict.fromkeys(keys))


def parse_host_port(key):
    try:
        after_at = key[len("vless://"):][key[len("vless://"):].rfind("@") + 1:]
        host_port = after_at.split("?")[0].split("#")[0]
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)
            return host.strip("[]"), int(port)
    except Exception:
        pass
    return None, None


def test_key(key):
    host, port = parse_host_port(key)
    if not host:
        return None
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception:
        return None
    best = None
    for family, socktype, proto, canonname, sockaddr in infos:
        start = time.time()
        try:
            s = socket.socket(family, socktype)
            s.settimeout(TEST_TIMEOUT)
            if s.connect_ex(sockaddr) == 0:
                elapsed = round((time.time() - start) * 1000, 1)
                if elapsed <= MAX_LATENCY_MS and (best is None or elapsed < best["latency_ms"]):
                    best = {"key": key, "host": host, "port": port, "latency_ms": elapsed}
            s.close()
        except Exception:
            pass
    return best


def filter_keys(keys, mode):
    if mode in COUNTRIES:
        kws = COUNTRIES[mode]
        return [k for k in keys if any(kw in k.lower() for kw in kws)]
    if mode == "other":
        return [k for k in keys if not any(kw in k.lower() for kw in ALL_KEYWORDS) and "russia" not in k.lower()]
    return keys


def main():
    keys = []
    for url in SOURCES:
        try:
            keys += fetch_keys(url)
        except Exception as e:
            print(f"⚠ Не удалось загрузить {url}: {e}")
    keys = list(dict.fromkeys(keys))
    print(f"Загружено {len(keys)} уникальных ключей")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(test_key, k): k for k in keys}
        done = 0
        for f in as_completed(futures):
            r = f.result()
            done += 1
            if r:
                results.append(r)
                print(f"[{done}/{len(keys)}] ✅ {r['host']}:{r['port']} — {r['latency_ms']} мс")

    results.sort(key=lambda x: x["latency_ms"])
    working_keys = [r["key"] for r in results]
    print(f"\nИтог: рабочих {len(working_keys)} из {len(keys)}")
    if not working_keys:
        print("Рабочих нет — не публикуем.")
        sys.exit(0)

    # Группировка по странам для stats
    groups = {}
    for mode in list(COUNTRIES) + ["other"]:
        cnt = sum(1 for r in results if any(kw in r["key"].lower() for kw in (COUNTRIES.get(mode) or []))) \
            if mode in COUNTRIES else None
        if mode == "other":
            others = [r for r in results if not any(kw in r["key"].lower() for kw in ALL_KEYWORDS)]
            groups["other"] = len(others)
        else:
            groups[mode] = cnt or 0

    # Записываем файлы подписки
    sub_b64 = base64.b64encode("\n".join(working_keys).encode()).decode()
    (REPO_DIR / "subscription.txt").write_text(sub_b64, encoding="utf-8")
    (REPO_DIR / "working_keys.txt").write_text("\n".join(working_keys) + "\n", encoding="utf-8")
    stats = {
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "total_working": len(working_keys),
        "groups": groups,
    }
    (REPO_DIR / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")

    # Коммит и пуш
    def git(*args):
        return subprocess.run(["git", *args], cwd=REPO_DIR, capture_output=True, text=True)

    git("add", "-A")
    diff = git("diff", "--cached", "--quiet")
    if diff.returncode == 0:
        print("Изменений нет — пушить нечего.")
        return
    git("commit", "-m", f"chore: update subscription ({stats['updated_at']}) [skip ci]")
    git("pull", "--rebase", "origin", "main")
    push = git("push", "origin", "main")
    print(push.stdout or "")
    print(push.stderr or "")
    if push.returncode == 0:
        print("✅ Опубликовано. Подписка для Happ:")
        print("https://raw.githubusercontent.com/FobiaLabs/vless-subscription/main/subscription.txt")


if __name__ == "__main__":
    main()
