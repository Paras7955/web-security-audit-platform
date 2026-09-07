FROM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS gitleaks-build

WORKDIR /src/gitleaks
ADD --checksum=sha256:6b2638a733b85619dc80bdf28e84e4fed7e526a761ab5c148fbf67695aea2115 \
    https://codeload.github.com/gitleaks/gitleaks/tar.gz/83d9cd684c87d95d656c1458ef04895a7f1cbd8e \
    /tmp/gitleaks-source.tar.gz
RUN tar --extract --gzip --file=/tmp/gitleaks-source.tar.gz --strip-components=1 \
    && go mod edit -require=golang.org/x/crypto@v0.55.0 \
    && go mod edit -require=golang.org/x/text@v0.39.0 \
    && go mod tidy \
    && CGO_ENABLED=0 go build -trimpath -tags gore2regex \
        -ldflags "-s -w -X=github.com/zricethezav/gitleaks/v8/version.Version=8.30.1-scopeharbor.1" \
        -o /out/gitleaks .

FROM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS osv-scanner-build

WORKDIR /src/osv-scanner
ADD --checksum=sha256:a75ba0030bd8df5df8f67450c6487a8c73f33e93766dd3c037ce1b5c676a767a \
    https://codeload.github.com/google/osv-scanner/tar.gz/a55e6f880f07c0de53e75ec97d8cec9966914e6f \
    /tmp/osv-scanner-source.tar.gz
RUN tar --extract --gzip --file=/tmp/osv-scanner-source.tar.gz --strip-components=1 \
    && go mod edit -require=github.com/go-git/go-git/v5@v5.19.2 \
    && go mod edit -require=golang.org/x/mod@v0.40.0 \
    && go mod edit -require=golang.org/x/text@v0.39.0 \
    && go mod tidy \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
        -o /out/osv-scanner ./cmd/osv-scanner/

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
COPY --from=gitleaks-build --chown=scopeharbor:scopeharbor /out/gitleaks /usr/local/bin/gitleaks
COPY --from=osv-scanner-build --chown=scopeharbor:scopeharbor /out/osv-scanner /usr/local/bin/osv-scanner
CMD ["python", "-m", "worker.main"]

FROM base AS relay
EXPOSE 8090
CMD ["uvicorn", "relay.main:app", "--host", "0.0.0.0", "--port", "8090", "--no-server-header", "--no-access-log", "--workers", "1"]
