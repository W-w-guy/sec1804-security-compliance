"""一条命令跑全部单测，且与宿主环境里的第三方 pytest 插件隔离。

为什么需要这个包装器（而不是直接 python -m pytest）：
    pytest 会在启动时自动加载环境里所有 pytest11 入口点。若机器上装了 ROS2
    （/opt/ros/*/lib/python3.12/site-packages），它会加载 launch_testing 相关插件，
    这些插件 import yaml；干净 venv 里没有 pyyaml，于是 pytest 在 **收集阶段**
    就以退出码 3 结束，一条用例都没跑 —— 这跟被测代码一点关系都没有。
    用 `-p no:launch_testing` 也不行：还有第二个插件
    launch_testing_ros_pytest_entrypoint 会因未知 hook 触发 INTERNALERROR。
    唯一稳妥做法是关掉插件自动加载（本项目不需要任何第三方 pytest 插件）。

用法：
    python tools/run_tests.py                # 95 passed
    python tools/run_tests.py -k vault -v    # 透传 pytest 参数
"""
from __future__ import annotations
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
               PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    cmd = [sys.executable, "-m", "pytest", "tests/"] + (argv or ["-q", "--no-header"])
    if not any(a.startswith("-q") for a in argv):
        cmd.append("-q")
    p = subprocess.run(cmd, cwd=HERE, env=env)
    return p.returncode


if __name__ == "__main__":
    raise SystemExit(main())
