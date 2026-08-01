FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN addgroup --system recallops && adduser --system --ingroup recallops recallops
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY migrations ./migrations
COPY evaluation ./evaluation
RUN pip install --no-cache-dir .
USER recallops
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=2)"]
CMD ["uvicorn", "recallops.main:app", "--host", "0.0.0.0", "--port", "8080"]
