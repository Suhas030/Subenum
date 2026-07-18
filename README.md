# subenum

A multi-source subdomain enumeration script that collects, dedupes, and probes subdomains — then sorts the live ones by HTTP status code into a clean report. Built for bug bounty recon.

## What it does

1. **Collects** subdomains from whichever of these tools you have installed:
   - [subfinder](https://github.com/projectdiscovery/subfinder)
   - [assetfinder](https://github.com/tomnomnom/assetfinder)
   - [findomain](https://github.com/Findomain/Findomain)
   - [sublist3r](https://github.com/aboul3la/Sublist3r)
   - crt.sh (via direct API query, no extra tooling needed)
2. **Merges & dedupes** everything into one clean list.
3. **Probes** every subdomain with [httpx](https://github.com/projectdiscovery/httpx) for liveness, status code, title, and tech stack.
4. **Sorts** live results by status code into a single readable report:

   ```
   200 :
   ----------------------------------------------
   https://app.example.com  [Login Page]
   https://www.example.com  [Example Domain]

   401 :
   ----------------------------------------------
   https://api.example.com  [-]

   403 :
   ----------------------------------------------
   https://admin.example.com  [Forbidden]
   ```

## Why

Most subdomain wordlist chains stop at "here's a giant list of hostnames." This script takes it one step further — the output is already triaged by response code, so 200s (worth manual review), 401/403s (worth auth-bypass testing), and 5xx (worth a second look) are visually separated instead of buried in a flat list.

## Requirements

**Hard requirements** (script exits without these):
- `curl`
- `jq`

**Optional** (auto-detected — the script tells you at runtime which ones it found and which it's missing):
- `subfinder`
- `assetfinder`
- `findomain`
- `sublist3r`
- `httpx` — without this, you still get a deduped subdomain list, just no liveness/status data

Install what you're missing:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
cargo install findomain
pip3 install sublist3r
sudo apt install jq curl
```

## Usage

```bash
chmod +x subenum.sh

./subenum.sh <domain> [output_dir]
```

Examples:

```bash
./subenum.sh example.com
./subenum.sh example.com ~/Hunts/recon
HTTPX_THREADS=100 HTTPX_RATE=300 ./subenum.sh example.com
```

| Env var | Default | Description |
|---|---|---|
| `HTTPX_THREADS` | `40` | httpx concurrency |
| `HTTPX_RATE` | `150` | httpx requests/sec rate limit |

Defaults are kept modest for low-resource machines — bump them up if you're running on something with more headroom.

## Output

Results are saved under `<output_dir>/<domain>/`:

| File | Description |
|---|---|
| `all_subdomains.txt` | Merged, deduped subdomain list (pre-httpx) |
| `live_full.txt` | TSV of every live host: URL, status, title, detected tech |
| `live_by_status.txt` | The main report — live hosts grouped by status code |
| `*.raw` | Per-source raw output, kept for debugging |

## Notes

- All tool output is suppressed — only the script's own progress/status lines print to the terminal.
- Every stage has error handling: bad domain input, missing dependencies, network failures, empty results, and tool timeouts all fail gracefully with a clear message instead of crashing mid-run.
- crt.sh is queried directly via its public API, so there's no extra dependency to set up for that source.

## License

MIT (or pick your preferred license before publishing)
