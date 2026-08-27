#!/usr/bin/env bash
set -euo pipefail

BOOTSTRAP_IMAGE="python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b"
BOOTSTRAP_ONLY=false
SKIP_OSV_UPDATE=false
ENV_FILE=".env"

usage() {
  printf '%s\n' \
    "Usage: ./scripts/setup.sh [--bootstrap-only] [--skip-osv-update] [--env-file PATH]" \
    "" \
    "Creates an idempotent local environment using Docker, updates the offline" \
    "OSV database, and starts ScopeHarbor. PATH must stay inside the repository."
}

while (($# > 0)); do
  case "$1" in
    --bootstrap-only)
      BOOTSTRAP_ONLY=true
      ;;
    --skip-osv-update)
      SKIP_OSV_UPDATE=true
      ;;
    --env-file)
      shift
      if (($# == 0)); then
        printf 'Missing value for --env-file.\n' >&2
        usage >&2
        exit 2
      fi
      ENV_FILE="$1"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

case "$ENV_FILE" in
  ""|*/*)
    printf 'The environment file must be a filename in the ScopeHarbor repository root.\n' >&2
    exit 2
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  printf 'Docker is required. Install Docker Desktop or Docker Engine before continuing.\n' >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  printf 'Docker Compose v2 is required (the "docker compose" command).\n' >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  printf 'The Docker daemon is not available. Start Docker and retry.\n' >&2
  exit 1
fi

printf 'Preparing ScopeHarbor environment with an isolated bootstrap container...\n'
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=16m,mode=0700 \
  --user "$(id -u):$(id -g)" \
  --volume "$REPO_ROOT:/workspace" \
  --workdir /workspace \
  "$BOOTSTRAP_IMAGE" \
  python scripts/bootstrap_env.py --output "$ENV_FILE" --template .env.example

if [[ "$BOOTSTRAP_ONLY" == true ]]; then
  printf 'Environment bootstrap complete.\n'
  exit 0
fi

if [[ "$SKIP_OSV_UPDATE" == false ]]; then
  printf 'Updating the isolated offline OSV advisory database...\n'
  docker compose --env-file "$ENV_FILE" --profile maintenance run --rm osv-db-update
else
  printf 'Skipping the offline OSV update by explicit request.\n'
fi

printf 'Building and starting ScopeHarbor...\n'
docker compose --env-file "$ENV_FILE" up --build --detach --wait

cat <<'EOF'

ScopeHarbor is ready.
  UI:           http://localhost:3001
  API docs:     http://localhost:8000/docs
  Readiness:    http://localhost:8000/ready
  Demo target:  http://localhost:3000

Stop without deleting data:
  docker compose down
EOF
