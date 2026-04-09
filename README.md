# CardForensics

Client-side smart card APDU trace forensic analyzer. Drop a macOS CryptoTokenKit log file and get a full security audit with zero data leaving your machine.

<p>
<img src="docs/assets/screenshot-landing.png" width="49%" alt="Landing page with Matrix APDU rain" />
<img src="docs/assets/screenshot-analysis.png" width="49%" alt="Analyzing a YubiKey PIV trace" />
</p>

## Features

- **Card identification** via ATR database (~5,100 cards including ~200 wildcard patterns), AID database (44 known applications), CLA/tag heuristics, and ATR regex pattern matching
- **Token identity extraction** aggregates serial number, firmware version, vendor, and CHUID fields (FASC-N, GUID, expiration) across all exchanges. Supports YubiKey and SafeNet eToken/Fusion hardware
- **ATR structural parsing** per ISO 7816-3: convention, protocols, historical bytes, TCK validation
- **Application identification** for EMV (Visa, Mastercard, Amex, JCB, Discover), OpenPGP, FIDO U2F/FIDO2, European eIDs (Belgian, German, Estonian, Spanish, Italian), GlobalPlatform, and health cards
- **Protocol reconstruction** with session boundaries, auth state machine tracking, and 61xx chaining
- **PIV analysis** covering 35 named data objects, 25 key references, 12 algorithm IDs (including ML-DSA-65), and certificate slot provisioning checks
- **SafeNet vendor decoding** for CLA=0x82 hardware serial retrieval, DF30 applet version, FF F3 key container mapping, and FF90 key template inventory
- **EMV tag dictionary** with ~50 TLV tags and value interpreters (PAN masking, CVM rules, cryptogram types, transaction counters)
- **Certificate viewer** with X.509 parsing via [Peculiar Ventures certificate viewer](https://github.com/PeculiarVentures/x509)
- **Default key detection** using AES-ECB/SCP03 brute-force against known management keys
- **Threat analysis** covering credential exposure, nonce replay, timing side-channels, bulk erasure patterns, orphaned keys, and ACL bypass
- **Security scoring** with weighted findings and provisioning-aware confidence gating
- **AI analysis** with optional per-exchange and session-level LLM analysis (requires your API key)
- **Forensic export** as deterministic JSON evidence package (schema v2.4) with token identity, ATR parse, AID resolution, and database coverage metadata

Everything runs in the browser. No data leaves your machine (unless AI is enabled with your API key).

## Live

[peculiarventures.github.io/cardforensics](https://peculiarventures.github.io/cardforensics/)

## Claude Skill

CardForensics includes a Claude skill for offline trace analysis. The skill runs the full analysis pipeline (card ID, token identity, threats, key brute-force, cert provisioning, scoring, sessions, annotations) and renders an interactive React dashboard with keyboard navigation.

```
skill/
  SKILL.md              # Skill definition and triggers
  scripts/
    analyze.js          # Full pipeline CLI (trace or ATR-only mode)
    render.js           # JSON-to-JSX dashboard renderer
```

Usage from the skill:

```bash
# Full trace analysis
npx vite-node skill/scripts/analyze.js trace.log --verbose | \
  npx vite-node skill/scripts/render.js --output dashboard.jsx

# ATR-only lookup
npx vite-node skill/scripts/analyze.js --atr "3B 7F 96 00 00 80 31 80 65 B0 85 03 00 EF 12 0F FE 82 90 00"
```

The dashboard supports arrow key / j/k navigation and auto-trims large traces to notable exchanges for artifact size limits.

## Supported Card Families

| Vendor | Card identification | Token identity | Vendor APDU decoding |
|--------|-------------------|----------------|---------------------|
| Yubico (YubiKey 5) | ATR + AID + version probe | Version, GUID | Standard PIV |
| Thales SafeNet eToken 5110 | CLA heuristics + FF F3 containers | Serial, version, CHUID | CLA=0x82 serial, DF30 version, FF F3/FF90 containers |
| Thales SafeNet Fusion | CLA heuristics + FF F3 containers | Serial, version, CHUID | CLA=0x82 serial, DF30 version, FF F3/FF90 containers |
| Generic PIV | AID selection | CHUID if populated | Standard PIV |
| EMV (Visa/MC/Amex) | AID + ATR | N/A | EMV TLV decoding |
| OpenPGP | AID | N/A | Standard |
| FIDO U2F/FIDO2 | AID | N/A | Standard |

## Development

```bash
npm install
npm run dev
```

## Test

```bash
npm test                 # regression suite (3 traces, 803 exchanges)
npm run test:update      # regenerate snapshots after intentional changes
```

The test suite covers SafeNet eToken, SafeNet Fusion, and YubiKey PIV traces with snapshot diffing for card ID, token metadata, threats, annotations, and export schema.

## Build

```bash
npm run build
# Output: dist/index.html (single-file, ~1,370KB)
# Copy to docs/ for GitHub Pages:
cp dist/index.html docs/index.html
```

## License

MIT © [Peculiar Ventures](https://peculiarventures.com)
