"""拒绝"看起来被接受、其实被忽略"的命令行参数。

★ 起因（2026-11-06，实测踩到）：`python tools/loop_verify_h.py --zip ~/ship_x.zip` 里的
  `--zip` 当时**根本不存在**，脚本也不读 sys.argv，于是它安静地去 ~/ 找了个**旧的**
  sec1804_sec5.zip 当成交付物检验，另一份包体被验成了 PASS。
  验收工具最危险的失败模式不是报错，而是验错了东西还打勾。
  现在：任何不认识的参数一律以非 0 退出并回显完整命令行。
"""
from __future__ import annotations
import sys


def reject_unknown(prog: str, allowed: tuple[str, ...] = ()) -> list[str]:
    """只允许白名单里的开关；出现其它参数就报错退出。返回被接受的参数列表。"""
    args = sys.argv[1:]
    ok = []
    for a in args:
        key = a.split("=", 1)[0]
        if key in allowed:
            ok.append(a)
        else:
            sys.stderr.write(
                f"[{prog}] 不认识的参数：{a}\n"
                f"  本脚本支持的参数：{', '.join(allowed) if allowed else '（无）'}\n"
                f"  完整命令行：{' '.join(sys.argv)}\n"
                "  提示：参数被静默忽略会导致「验错了交付物还打勾」，所以这里直接失败。\n")
            raise SystemExit(2)
    return ok
