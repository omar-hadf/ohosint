---
name: tor-proxy
description: "Use when any CLI tool or Python script needs to route traffic through Tor as a SOCKS5 proxy — especially without sudo/root. Covers userspace tor install (apt-get download + dpkg -x), startup, IP verification, env-var proxying for httpx/requests/curl, and known pitfalls (holehe has no --proxy flag; socksio dependency; DNS leaks)."
---

# /tor-proxy

Route any tool's traffic through Tor without root, verified on this machine (tor 0.4.6.10, Python 3.10, Ubuntu 22.04 base).

## When to use

- A scanner/scraper is rate-limited or IP-flagged and you need a different exit IP
- You need OPSEC (hide origin IP) for OSINT recon
- No sudo available (shared box, CTF lab) — everything below installs into user space

## 1. Install tor WITHOUT sudo (userspace)

```bash
mkdir -p ~/tools/tor && cd ~/tools/tor
apt-get download tor                 # fetches .deb into cwd
dpkg -x tor_*.deb tree               # extract into ./tree
./tree/usr/bin/tor --version         # sanity check
```

If `ldd tree/usr/bin/tor | grep "not found"` shows missing libs, `apt-get download` those packages too and `dpkg -x` them into the same tree, then run with `LD_LIBRARY_PATH=$PWD/tree/usr/lib/x86_64-linux-gnu`.

## 2. Start + verify

```bash
nohup ./tree/usr/bin/tor \
  --SocksPort 127.0.0.1:9050 \
  --DataDirectory ~/tools/tor/data > ~/tools/tor/tor.log 2>&1 &

# wait for "Bootstrapped 100% (done)" in tor.log (~15-30s)
grep "Bootstrapped 100" ~/tools/tor/tor.log

# verify exit IP — use --socks5-hostname, NOT --socks5 (DNS must resolve through tor)
curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# → {"IsTor":true,"IP":"<exit-ip>"}
```

## 3. Route tools through it

### Env var (works for httpx-based tools: holehe, maigret-style scanners)

```bash
pip install --user socksio            # REQUIRED: httpx needs it for socks5:// scheme
ALL_PROXY=socks5://127.0.0.1:9050 holehe victim@example.com
```

httpx `AsyncClient()` defaults to `trust_env=True`, so it honors `ALL_PROXY`/`HTTPS_PROXY`. There is **no CLI flag** on holehe ≤1.61 (`--proxy` errors with "unrecognized arguments").

### curl

```bash
curl --socks5-hostname 127.0.0.1:9050 https://example.com
```

### requests (python)

```bash
pip install --user "requests[socks]"
```
```python
proxies = {"http": "socks5h://127.0.0.1:9050",   # socks5h = DNS via tor
           "https": "socks5h://127.0.0.1:9050"}
r = requests.get(url, proxies=proxies, timeout=30)
```

## 4. Rotate identity (new exit IP)

Simplest reliable way without control-port auth:

```bash
pkill -f "tor --SocksPort" ; rm -rf ~/tools/tor/data
# then restart as in step 2
```

## Pitfalls (all hit in practice)

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: socksio` | httpx socks support not installed | `pip install --user socksio` |
| Silent empty results, no error | tool got connection refused mid-bootstrap | confirm `Bootstrapped 100%` first |
| `tortree/usr/bin/tor: No such file or directory` while file exists | wrong path / subshell quirk | run with explicit relative or absolute path |
| Sites STILL rate-limit through tor | Cloudflare/WAF blocks known exits (in one test 77/81 blocked sites stayed blocked) | tor fixes IP bans, NOT broken modules — use a maintained tool (e.g. `user-scanner` uses TLS impersonation instead) |
| DNS leak | using `--socks5` / `socks5://` in curl/requests | always `--socks5-hostname` / `socks5h://` |

## Cleanup

```bash
pkill -f "tor --SocksPort"; rm -rf ~/tools/tor
```
