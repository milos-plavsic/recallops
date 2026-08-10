FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-compile .

FROM gcr.io/distroless/cc-debian13@sha256:d97bc0a941b8d4be647dc0ee75b264ddbb772f1ac5ba690a4309c00723b23775 AS runtime

ENV PATH=/usr/local/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=builder /usr/local /usr/local
COPY --from=builder /usr/lib/x86_64-linux-gnu/libffi.so.8* /usr/lib/x86_64-linux-gnu/
COPY migrations ./migrations
COPY evaluation ./evaluation
COPY infra/certs/cockroach-cloud-root.crt ./certs/cockroach-cloud-root.crt
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=2)"]
CMD ["uvicorn", "recallops.main:app", "--host", "0.0.0.0", "--port", "8080"]
