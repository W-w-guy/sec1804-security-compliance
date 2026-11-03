FROM python:3.12-slim

# 默认用清华源，国内构建更快；需要官方源：
#   docker build --build-arg PIP_INDEX_URL=https://pypi.org/simple .
ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# 装的是 requirements-dev：交付物里带测试，买家在容器里也要能一条命令跑全绿。
# （B9 在容器内跑时因缺 httpx 直接异常 —— TestClient 依赖 httpx）
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -i ${PIP_INDEX_URL} -r requirements-dev.txt

COPY app ./app
COPY tools ./tools
COPY data ./data
COPY tests ./tests
COPY pytest.ini run.py README.md ./

RUN useradd -r -u 10001 appuser && mkdir -p /app/.kms && chown -R appuser /app
USER appuser
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
