FROM ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks
FROM ghcr.io/google/osv-scanner:v2.3.8@sha256:64e86bec6df2466feea5137fc7c78fb3b7c21ec077f014d7130f64810e50676b AS osv-scanner

FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 scopeharbor \
    && useradd --uid 10001 --gid scopeharbor --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin scopeharbor

WORKDIR /app

COPY backend/requirements.txt ./requirements.txt
RUN pip install --require-hashes --requirement requirements.txt

COPY --chown=scopeharbor:scopeharbor backend/ ./
COPY --chown=scopeharbor:scopeharbor shared/ ./shared/
COPY --chown=scopeharbor:scopeharbor config/ ./config/

RUN mkdir -p /app/artifacts /app/repositories /tmp/scopeharbor-repo-staging /var/lib/osv-scanner \
    && chown -R scopeharbor:scopeharbor /app/artifacts /app/repositories /tmp/scopeharbor-repo-staging /var/lib/osv-scanner \
    && chmod 0700 /app/artifacts /app/repositories /tmp/scopeharbor-repo-staging /var/lib/osv-scanner

USER 10001:10001
EXPOSE 8000

FROM base AS api
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--no-access-log"]

FROM base AS worker
COPY --from=gitleaks --chown=scopeharbor:scopeharbor /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=osv-scanner --chown=scopeharbor:scopeharbor /osv-scanner /usr/local/bin/osv-scanner
CMD ["python", "-m", "worker.main"]

FROM base AS relay
EXPOSE 8090
CMD ["uvicorn", "relay.main:app", "--host", "0.0.0.0", "--port", "8090", "--no-server-header", "--no-access-log", "--workers", "1"]
