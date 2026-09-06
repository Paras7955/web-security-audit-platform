#!/usr/bin/env bash
set -euo pipefail

BOOTSTRAP_IMAGE="python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b"
BOOTSTRAP_ONLY=false
SKIP_OSV_UPDATE=false
ENV_FILE=".env"
PROJECT_NAME="scopeharbor"

usage() {
  printf '%s\n' \
    "Usage: ./scripts/setup.sh [--bootstrap-only] [--skip-osv-update] [--env-file FILE] [--project-name NAME]" \
    "" \
    "Creates an idempotent local environment using Docker, updates the offline" \
    "OSV database, and starts ScopeHarbor. FILE must be .env or a .env.* file" \
    "in the repository root so Docker always excludes it from build contexts."
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
    --project-name)
      shift
      if (($# == 0)); then
        printf 'Missing value for --project-name.\n' >&2
        usage >&2
        exit 2
      fi
      PROJECT_NAME="$1"
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

if [[ ! "$ENV_FILE" =~ ^\.env(\.[A-Za-z0-9][A-Za-z0-9._-]*)?$ ]]; then
  printf 'The environment file must be .env or a .env.* filename in the ScopeHarbor repository root.\n' >&2
  exit 2
fi
case "$ENV_FILE" in
  .env.[eE][xX][aA][mM][pP][lL][eE])
    printf '.env.example is the tracked public template and cannot be used as an output environment file.\n' >&2
    exit 2
    ;;
esac
if [[ -e "$ENV_FILE" && ( ! -f "$ENV_FILE" || -L "$ENV_FILE" ) ]]; then
  printf 'The environment file path must be a regular file, not a directory or symbolic link.\n' >&2
  exit 2
fi

if [[ ! "$PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
  printf 'The Compose project name must start with a lowercase letter or digit and contain only lowercase letters, digits, hyphens, or underscores.\n' >&2
  exit 2
fi

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
BOOTSTRAP_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/scopeharbor-bootstrap.XXXXXX")"
cleanup_bootstrap() {
  rm -rf -- "$BOOTSTRAP_TEMP_DIR"
}
trap cleanup_bootstrap EXIT
if [[ -f "$ENV_FILE" ]]; then
  cp -- "$ENV_FILE" "$BOOTSTRAP_TEMP_DIR/environment"
fi
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=16m,mode=0700 \
  --user "$(id -u):$(id -g)" \
  --volume "$REPO_ROOT:/workspace:ro" \
  --volume "$BOOTSTRAP_TEMP_DIR:/output" \
  --workdir /workspace \
  "$BOOTSTRAP_IMAGE" \
  python scripts/bootstrap_env.py --output /output/environment --template .env.example
mv -f -- "$BOOTSTRAP_TEMP_DIR/environment" "$ENV_FILE"
chmod 0600 "$ENV_FILE"

if [[ "$BOOTSTRAP_ONLY" == true ]]; then
  printf 'Environment bootstrap complete.\n'
  exit 0
fi

if [[ "$SKIP_OSV_UPDATE" == false ]]; then
  printf 'Updating the isolated offline OSV advisory database...\n'
  SCOPEHARBOR_ENV_FILE="$ENV_FILE" docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
    --profile maintenance run --rm osv-db-update
else
  printf 'Skipping the offline OSV update by explicit request.\n'
fi

printf 'Building and starting ScopeHarbor...\n'
SCOPEHARBOR_ENV_FILE="$ENV_FILE" docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" \
  up --build --detach --wait

FRONTEND_ADDRESS="$(SCOPEHARBOR_ENV_FILE="$ENV_FILE" docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" port frontend 3000)"
BACKEND_ADDRESS="$(SCOPEHARBOR_ENV_FILE="$ENV_FILE" docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" port backend 8000)"
DEMO_ADDRESS="$(SCOPEHARBOR_ENV_FILE="$ENV_FILE" docker compose --project-name "$PROJECT_NAME" --env-file "$ENV_FILE" port juice-shop 3000)"
FRONTEND_PORT="${FRONTEND_ADDRESS##*:}"

cat <<EOF

ScopeHarbor is ready.
  UI:           http://localhost:$FRONTEND_PORT
  API docs:     http://$BACKEND_ADDRESS/docs
  Readiness:    http://$BACKEND_ADDRESS/ready
  Demo target:  http://$DEMO_ADDRESS

Stop without deleting data:
  SCOPEHARBOR_ENV_FILE=$ENV_FILE docker compose --project-name $PROJECT_NAME --env-file $ENV_FILE down
EOF
