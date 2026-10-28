FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    MIZAN_BIND_HOST=0.0.0.0 \
    MIZAN_DB_PATH=/app/data/mizan.sqlite3

WORKDIR /app
RUN groupadd --gid 10001 mizan \
    && useradd --uid 10001 --gid mizan --no-create-home --shell /usr/sbin/nologin mizan \
    && mkdir -p /app/data \
    && chown -R mizan:mizan /app \
    && chmod 0700 /app/data

COPY --chown=mizan:mizan . /app
USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '8000'), timeout=2).read()" || exit 1

CMD ["python", "server.py"]
