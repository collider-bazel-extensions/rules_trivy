#!/usr/bin/env bash
# The test sandbox has no network (.bazelrc sets
# --sandbox_default_allow_network=false), so the scans in this package can't
# have fetched anything: they ran on the pinned data alone. Fails if a
# connection to ghcr.io (by name, or a public IP if DNS fails) succeeds.
set -euo pipefail
python3 -I - <<'PY'
import socket, sys
for host in ("ghcr.io", "140.82.112.33", "1.1.1.1"):
    try:
        socket.create_connection((host, 443), timeout=5).close()
    except OSError as e:
        print("blocked: {}:443 ({})".format(host, e))
        continue
    print("FAIL: connected to {}:443 -- the sandbox has network; "
          "run with --sandbox_default_allow_network=false".format(host), file=sys.stderr)
    sys.exit(1)
print("PASS")
PY
