FROM python:3.12-slim

# 默认用清华源，国内构建更快；需要官方源：
#   docker build --build-arg PIP_INDEX_URL=https://pypi.org/simple .
ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# 装的是 requirements.lock（全闭包 36 个包）：镜像里的版本必须与报告里扫描的版本、
# 与跑出 95 项单测的版本**逐字一致**，否则「无未处理高危」这句话对镜像就不成立。
# （早先这里装 requirements.txt，间接依赖随 resolver 漂移；dep_scan/cve_scan 也会对不上。）
# 交付物里带测试，买家在容器里也要能一条命令跑全绿，所以 lock 含 dev 依赖。
COPY requirements.txt requirements-dev.txt requirements.lock ./
RUN pip install --no-cache-dir -i ${PIP_INDEX_URL} -r requirements.lock

COPY app ./app
COPY tools ./tools
COPY data ./data
COPY tests ./tests
# reports/ 必须进镜像：验收点 7 的两份证据（dep_scan.json / cve_scan.json）在镜像内可复核，
# `python tools/cve_scan.py --offline` 与 tests/test_deps.py 都读它。
# ★ 这条是容器实测补的：只 COPY 代码不 COPY reports，容器里 test_deps 4 项直接红
#   ——Windows 上永远不会暴露（工作目录里 reports/ 本来就在）。
COPY reports ./reports
COPY pytest.ini run.py README.md CHANGELOG.md ./

RUN useradd -r -u 10001 appuser && mkdir -p /app/.kms && chown -R appuser /app
USER appuser
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
