FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/agent_black_hole.db

RUN apt-get update \
 && apt-get install -y --no-install-recommends gosu \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 harbour \
 && useradd --system --uid 10001 --gid harbour --home-dir /app harbour \
 && mkdir -p /app /data \
 && chown -R harbour:harbour /app /data

WORKDIR /app
COPY --chown=harbour:harbour requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=harbour:harbour app ./app
COPY --chown=harbour:harbour entrypoint.sh ./entrypoint.sh
RUN chmod 0555 /app/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
