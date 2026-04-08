# CardForensics

Client-side PIV/GlobalPlatform smart card APDU trace forensic analyzer. Drop a macOS CryptoTokenKit log file and get:

- **Card identification** via ATR database (85 cards) + AID/CLA/tag heuristics
- **Protocol reconstruction** — session boundaries, auth state machine, 61xx chaining
- **Certificate viewer** — X.509 parsing with [Peculiar Ventures certificate viewer](https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io)
- **Default key detection** — AES-ECB/SCP03 brute-force against known management keys
- **Threat analysis** — credential exposure, nonce replay, timing side-channels, ACL bypass
- **Security scoring** — weighted findings with provisioning-aware confidence gating
- **AI analysis** — optional per-exchange and session-level LLM analysis
- **Forensic export** — deterministic JSON evidence package

Everything runs in the browser. No data leaves your machine (unless AI is enabled with your API key).

## Live

[cardforensics.peculiarventures.com](https://peculiarventures.github.io/cardforensics/)

## Development

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
# Output: dist/index.html (single-file, ~870KB)
# Copy to docs/ for GitHub Pages:
cp dist/index.html docs/index.html
```

## License

MIT © [Peculiar Ventures](https://peculiarventures.com)
