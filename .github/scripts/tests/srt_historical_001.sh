#!/usr/bin/env bash
set -euo pipefail
test "$(uname -s)" = Linux
test "$(uname -m)" = aarch64
uname -a
ROOT="$RUNNER_TEMP/srt-historical-001"
mkdir -p "$ROOT/node" "$ROOT/install" "$ROOT/fixture"
ORIGINAL=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)
restore() {
  local rc=$?
  trap - EXIT
  sudo sysctl -w "kernel.apparmor_restrict_unprivileged_userns=$ORIGINAL" || rc=1
  exit "$rc"
}
trap restore EXIT
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
sudo apt-get update
sudo apt-get install -y --no-install-recommends ca-certificates curl xz-utils bubblewrap socat ripgrep python3
timeout 20s bwrap --unshare-pid --unshare-user --cap-drop ALL --ro-bind / / --proc /proc true
curl -fLsS --retry 3 --max-time 180 -o "$ROOT/node.tar.xz" https://nodejs.org/dist/v22.21.1/node-v22.21.1-linux-arm64.tar.xz
echo "e660365729b434af422bcd2e8e14228637ecf24a1de2cd7c916ad48f2a0521e1  $ROOT/node.tar.xz" | sha256sum -c -
tar -xJf "$ROOT/node.tar.xz" --strip-components=1 -C "$ROOT/node"
export PATH="$ROOT/node/bin:$PATH"
test "$(node -p 'process.arch')" = arm64
test "$(node --version)" = v22.21.1
curl -fLsS --retry 3 --max-time 180 -o "$ROOT/srt-0.0.1.tgz" https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/-/sandbox-runtime-0.0.1.tgz
export HISTORICAL_ROOT="$ROOT"
python3 - <<'PY'
import base64, hashlib, os
from pathlib import Path
archive = Path(os.environ["HISTORICAL_ROOT"]) / "srt-0.0.1.tgz"
expected = "sha512-8ueLnIkkwirTXxVKBPpEUawb0Ql5sGWyCOEyuGWRQrY2I6f6ypBHuAXABiQISVVCGu8rbf9kHOnwJZJ9mLUnYA=="
observed = "sha512-" + base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode("ascii")
if observed != expected:
    raise SystemExit("Historical npm SRI mismatch")
print("HISTORICAL_SRI_VERIFIED", observed)
PY
timeout 240s npm install --prefix "$ROOT/install" --ignore-scripts --no-audit --no-fund --save-exact "$ROOT/srt-0.0.1.tgz"
PACKAGE="$ROOT/install/node_modules/@anthropic-ai/sandbox-runtime"
test "$(node -p "require('$PACKAGE/package.json').name")" = @anthropic-ai/sandbox-runtime
test "$(node -p "require('$PACKAGE/package.json').version")" = 0.0.1
echo "HISTORICAL_MANIFEST_VERSION=0.0.1"
CLI_VERSION=$(node "$PACKAGE/dist/cli.js" --version)
echo "Historical CLI reports $CLI_VERSION; manifest and SRI establish actual version 0.0.1."
python3 - <<'PY'
import json, os
from pathlib import Path
root = Path(os.environ["HISTORICAL_ROOT"])
fixture = root / "fixture"
(fixture / "readable").write_text("public-arm-data")
(fixture / "secret").write_text("private-historical-secret")
(fixture / "protected").write_text("unchanged")
settings = {"permissions": {"allow": [f"Edit({fixture})"],
                           "deny": [f"Read({fixture / 'secret'})",
                                    f"Edit({fixture / 'protected'})"]}}
(root / "settings.json").write_text(json.dumps(settings))
(root / "probe.py").write_text("""import errno, pathlib, subprocess, sys
p = pathlib.Path(sys.argv[1])
assert sys.stdin.readline() == "native-input\\n"
assert (p / "readable").read_text() == "public-arm-data"
(p / "allowed").write_text("native-arm-write")
assert (p / "allowed").read_text() == "native-arm-write"
# This release masks denied files with /dev/null instead of returning EPERM.
try:
    hidden = (p / "secret").read_text()
except OSError as error:
    assert error.errno in (errno.EACCES, errno.EPERM, errno.ENOENT), error
else:
    assert hidden == "", "Denied secret contents remained readable"
try:
    (p / "protected").write_text("bypassed")
except OSError as error:
    assert error.errno in (errno.EACCES, errno.EPERM, errno.EROFS), error
else:
    raise AssertionError("Write denial bypassed")
assert subprocess.check_output(["cat", str(p / "allowed")], text=True) == "native-arm-write"
print("HISTORICAL_0_0_1_ARM64_IO_AND_FILESYSTEM_ENFORCEMENT_OK")
""")
PY
cd "$ROOT/fixture"
test "$(cat secret)" = private-historical-secret
test -w protected
printf -v COMMAND 'python3 %q %q' "$ROOT/probe.py" "$ROOT/fixture"
printf 'native-input\n' | timeout --kill-after=5s 60s node "$PACKAGE/dist/cli.js" --settings "$ROOT/settings.json" "$COMMAND" | tee "$ROOT/result.log"
grep -Fxq HISTORICAL_0_0_1_ARM64_IO_AND_FILESYSTEM_ENFORCEMENT_OK "$ROOT/result.log"
test "$(cat protected)" = unchanged
test "$(cat allowed)" = native-arm-write
{
  echo '## Historical Sandbox Runtime 0.0.1 native Arm64 validation'
  echo 'SRI and package.json version verified; native stdin/stdout, allowed reads/writes, denied secret masking, and denied writes passed.'
  echo 'Node 22.21.1 on Linux AArch64; this is historical compatibility evidence, not security certification or a deployment recommendation.'
} >> "$GITHUB_STEP_SUMMARY"
