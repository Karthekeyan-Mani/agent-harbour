#!/bin/sh
set -eu
chown harbour:harbour /data
exec gosu harbour uvicorn app.main:app --host 0.0.0.0 --port 8080 --no-server-header --proxy-headers --forwarded-allow-ips '*'
