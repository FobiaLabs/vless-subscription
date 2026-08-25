#!/usr/bin/env python3
# make_simple_sub.py — максимально простая подписка: только vless, только base64,
# без заголовков, без эмодзи, имена = host + Mb. Для мобильного Happ.
import base64

src = "top20_subscription.txt"
dst = "top20_mobile.txt"

d = base64.b64decode(open(src, "rb").read()).decode("utf-8")
lines = [l for l in d.splitlines() if l.startswith("vless://")]

out = "\n".join(lines)
open(dst, "w", newline="\n").write(base64.b64encode(out.encode()).decode())
print(f"ключей: {len(lines)} (только vless) -> {dst}")
