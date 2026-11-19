#!/bin/bash
# End-to-end test of the agent on one Linux distribution: boots the image
# with systemd, installs the agent with install.sh, runs scenario.sh and
# checks what reached a fake ingest server.
#
#   test/distro/run.sh <image> <os-release ID> [rsyslog: yes|no]
#
# Needs Docker (privileged containers), Go and python3. The binary is built
# from the working tree. Example: test/distro/run.sh almalinux:9 almalinux yes
# E2E_KEEP=1 leaves the container running for a look inside.
set -eu
IMAGE=$1 DISTRO=$2 RSYSLOG=${3:-no}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
NAME=e2e-$(echo "$IMAGE" | tr '/:.' '---')
WORK=$(mktemp -d)
PORT=${E2E_PORT:-18999}

cleanup() {
  [ -n "${E2E_KEEP:-}" ] || docker rm -f "$NAME" >/dev/null 2>&1 || true
  [ -n "${INGEST_PID:-}" ] && kill "$INGEST_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "== $IMAGE: build"
(cd "$REPO" && CGO_ENABLED=0 go build -o "$WORK/yomins-agent" ./cmd/yomins-agent)
docker build -q -t "$NAME" --build-arg BASE="$IMAGE" "$HERE" >/dev/null

# The fake ingest server runs on the host, reachable from the container
# through the bridge's gateway.
GATEWAY=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
if [ -z "${E2E_INGEST_DIR:-}" ]; then
  E2E_INGEST_DIR=$WORK/ingest
  python3 "$HERE/fakeingest.py" "$E2E_INGEST_DIR" "$PORT" &
  INGEST_PID=$!
  sleep 1
fi

echo "== $IMAGE: boot"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --hostname "$NAME" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v "$WORK/yomins-agent:/e2e/yomins-agent:ro" -v "$REPO:/e2e/repo:ro" "$NAME" >/dev/null
for _ in $(seq 1 30); do
  state=$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)
  case $state in running|degraded) break ;; esac
  sleep 2
done
echo "systemd: ${state:-not up}"

echo "== $IMAGE: scenario"
docker exec "$NAME" bash /e2e/repo/test/distro/scenario.sh "$NAME" "http://$GATEWAY:$PORT/v1/push" "$RSYSLOG"

echo "== $IMAGE: checks"
python3 "$HERE/check.py" "$E2E_INGEST_DIR/$NAME" "$DISTRO"
