"""Read only the Quick Tunnel URL; do not print raw service or request logs."""

import re
import subprocess

result = subprocess.run(
    ["docker", "compose", "logs", "--no-color", "--tail", "200", "tunnel"],
    capture_output=True,
    text=True,
    check=True,
)
urls = re.findall(r"https://[a-z0-9-]+\.trycloudflare\.com", result.stdout + result.stderr)
if not urls:
    raise SystemExit("Tunnel URL is not ready yet; retry make tunnel-url shortly.")
print(urls[-1])
