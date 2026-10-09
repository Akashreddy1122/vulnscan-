# Malware Scan API — hardened, non-root image.
# NOTE: run exactly ONE worker process. Rate limiting, background monitors and
# the scan queue are in-process; SQLite is single-writer. Scale out with agents
# and read replicas (see docs/ARCHITECTURE.md), not uvicorn workers.
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MALWARESCAN_DATA=/data

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY malwarescan ./malwarescan
COPY scripts ./scripts

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin msscan \
 && mkdir -p /data && chown -R msscan:msscan /data /app
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "malwarescan.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]
