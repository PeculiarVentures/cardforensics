---
name: cardforensics
description: >
  Smart card APDU trace forensic analyzer. Use this skill whenever the user uploads
  a smart card log file (.log), mentions APDU trace analysis, asks about PIV or
  GlobalPlatform card behavior, wants to debug smart card provisioning, needs to
  identify a card from its ATR or APDU traffic, or asks about card security (default
  keys, credential exposure, certificate status). Also trigger on: CardForensics,
  CryptoTokenKit log, eToken, YubiKey trace, SafeNet, PIV provisioning, SCP03
  authentication debugging, smart card forensics, CHUID, FASC-N, card management
  key, APDU replay, or card compliance audit. This skill runs a full pipeline:
  card identification (5,100+ ATR database), protocol reconstruction, TLV annotation,
  certificate provisioning checks, default key brute-force, threat detection, security
  scoring, token identity extraction, and compliance profiling — all client-side
  with no data leaving the machine.
---

# CardForensics — Smart Card APDU Trace Forensic Analyzer

This skill wraps the full [CardForensics](https://github.com/PeculiarVentures/cardforensics) analysis pipeline. It takes a macOS CryptoTokenKit APDU log file and produces a comprehensive forensic analysis covering card identification, security threats, certificate status, protocol correctness, and token identity.

## Setup

```bash
cd /home/claude
git clone https://github.com/PeculiarVentures/cardforensics.git
cd cardforensics && npm install
```

If the repo is already cloned, skip to running the analyzer.

## How to Run

The skill has two scripts in `skill/scripts/`:
- `analyze.js` — runs the analysis pipeline, outputs JSON
- `render.js` — takes analysis JSON, produces a React dashboard artifact

### Full Trace Analysis (primary)

**Step 1: Run the analyzer**

```bash
cd /home/claude/cardforensics
npx vite-node skill/scripts/analyze.js <path-to-log> --verbose > /tmp/cf-analysis.json 2>/dev/null
```

- `<path-to-log>` — uploaded CryptoTokenKit `.log` file (check `/mnt/user-data/uploads/`)
- `--verbose` — include full timeline with per-exchange data (recommended for dashboard)

**Step 2: Enrich with AI analysis**

Read `/tmp/cf-analysis.json` and add these fields:

1. **`d.summary`** — 3-5 sentence executive summary covering card type, lifecycle phase, critical findings, cert status, and compliance observations.

2. **`d.sessions[i].summary`** — 1-2 sentence summary per session describing what happened (e.g., "Card discovery and enumeration. Probes AIDs, reads firmware version, CHUID, certificate slots.").

3. **`t.explanation`** on timeline exchanges — 1-2 sentence explanation covering what the host is doing, why, and security implications. Add to ALL exchanges with meaningful annotations, not just flagged ones. Cover: SELECT commands, cert reads, GET DATA results, GEN AUTH sequences, credential operations, vendor probes, key container operations. Exchanges without explanations show decoded fields at full width; exchanges with explanations show a side-by-side AI ANALYSIS panel.

Write the enriched JSON to `/tmp/cf-enriched.json`.

**Step 3: Render the dashboard**

```bash
cat /tmp/cf-enriched.json | npx vite-node skill/scripts/render.js \
  --output /mnt/user-data/outputs/cardforensics-dashboard.jsx
```

Then present the artifact with `present_files`. The dashboard includes:
- **Letter grade** (A-F) with hover tooltip showing score breakdown
- **AI summary** panel at top with executive forensic summary
- **Threat badges** with severity and clickable exchange links
- **Session dividers** with sticky headers, colored bars, time ranges, error counts, AI summaries, operation badges. Collapsible.
- **Filter bar** with text search, errors-only toggle, hide-GET-DATA toggle
- **Play/pause** with sticky controls and keyboard navigation (arrows, j/k, space)
- **Exchange detail** with two-column layout (decoded fields + AI analysis)
- **Spec reference badges** linking to ISO 7816-4, SP 800-73-4, GP SCP03
- **Decoded fields** for CHUID, credentials, version, discovery objects, key containers
- **Annotated hex** with TLV-colored segments and hover tooltips
- **PV certificate viewer** (vendored @peculiar/certificates-viewer) for cert exchanges
- **Findings tab** with severity filter buttons, cert slot links, PV viewer in threats, key check, compliance bar, object ledger
- **Identity tab** with card ID, token identity, CHUID fields

After presenting the dashboard, add a brief prose summary highlighting the most important findings for the user's question.

### ATR Lookup (secondary)

```bash
cd /home/claude/cardforensics
npx vite-node skill/scripts/analyze.js --atr-only <hex>
```

ATR lookup mode returns minimal JSON — present as text, no dashboard needed.

## Understanding the Output

The analyzer outputs JSON with these sections. Read the full output before responding. Present results based on what the user is asking about — don't dump the entire JSON.

### `card_identification`

What card is this? Uses ATR database (5,100+ entries from PV card-database.json and pcsc-tools), AID matching, and CLA/tag heuristics.

- `name` — card family ("YubiKey (PIV)", "SafeNet eToken 5110", "Belgian eID", etc.)
- `vendor` — manufacturer ("Yubico", "Thales (SafeNet)", "NXP", etc.)
- `confidence` — 0-100%. Below 60% means heuristic guess only.
- `signals` — evidence used (ATR match, AID selected, vendor-specific tags)

### `token_identity`

Hardware-level identity extracted from response data:

- `serial` — hardware serial number (YubiKey: INS 0x01; SafeNet: CLA 0x82 CA)
- `version` — firmware/applet version (YubiKey: INS 0xFD; SafeNet: DF30)
- `vendor` — detected from command patterns
- `chuid` — PIV Card Holder Unique Identifier:
  - `guid` — 16-byte UUID identifying this credential
  - `fascn` — Federal Agency Smart Credential Number (BCD-encoded)
  - `expiration` — credential expiration date (YYYY-MM-DD)
  - `hasSignature` — whether the CHUID has an issuer digital signature
  - `cardholderUUID` — optional persistent person identifier

### `security_score`

Overall security rating 0-100 (higher = fewer findings). Categories:
- `score` — numeric score
- `label` — "Low Findings", "Moderate Risk", "High Risk", "Critical"
- `breakdown` — per-category deductions with reasons

### `threats`

Each threat has:
- `severity` — critical, high, medium, low
- `title` — one-line summary
- `detail` — full explanation with remediation guidance
- `exchange_ids` — which APDU exchanges triggered the finding

Common threat IDs:
| ID | Severity | What it means |
|----|----------|---------------|
| `default-mgmt-key` | critical | Card uses a known default management key (01020304... or similar) |
| `cleartext-credential` | critical | PIN or PUK visible in plaintext in the trace |
| `nonce-replay` | high | Same challenge nonce reused across auth attempts |
| `unsigned-chuid` | medium | CHUID lacks issuer asymmetric signature |
| `weak-pin-length` | medium | PIN shorter than 6 digits |
| `unauth-cert-read` | low | Certificates readable without prior authentication |
| `timing-side-channel` | medium | Measurable timing variation in auth responses |
| `acl-bypass-attempt` | high | Operations attempted without required authentication |

### `key_check`

SCP03 management key brute-force against known default keys:
- `keys_tested` — number of known key patterns tested
- `pairs_tested` — INITIALIZE UPDATE / EXTERNAL AUTHENTICATE pairs found
- `matches` — **critical if non-empty** — card accepts a known default key

### `cert_provisioning`

PIV certificate slot status:
- `probed` — slots the host checked (5FC105 = PIV Auth, 5FC10A = Sig, 5FC10B = KeyMgmt, 5FC101 = CardAuth)
- `populated` — slots with certificates present
- `absent` — slots queried but empty
- `required_populated` — whether all four mandatory PIV slots are filled
- `all_populated` — whether every probed slot has a certificate

### `integrity`

Trace completeness:
- `complete` — full capture, no gaps
- `fragment` — starts mid-operation (missing initial SELECT)
- `filtered` — large time gaps suggest selective capture
- `snippet` — too few exchanges for confident analysis

### `compliance`

APDU standard conformance:
- `standard_pct` — percentage of exchanges using standard ISO/PIV instructions
- `proprietary_pct` — percentage using vendor-specific instructions
- `proprietary_ins` — which non-standard INS codes were observed

### `sessions`

Logical session boundaries with high-level operation summaries. Each session represents a complete SELECT → authenticate → operate → close cycle.

### `object_ledger`

Every data object read or written during the trace, with tag, name, size, and operation phase.

### `notable_annotations`

Exchanges flagged as `bug` (protocol error), `warn` (unexpected), or `key` (credential material observed). Use these to pinpoint specific problems.

## How to Present Results

### User is debugging provisioning

Focus on:
1. `notable_annotations` with `bug` flags — these are protocol sequencing errors
2. `cert_provisioning` — which slots are populated vs absent
3. `sessions` — show the operation flow so they can see where it went wrong
4. `object_ledger` — what was written and in what order

### User wants a security audit

Focus on:
1. `security_score` — lead with the overall rating
2. `threats` — list all findings by severity, critical first
3. `key_check` — highlight if default keys were found (this is the worst finding)
4. `token_identity.chuid.hasSignature` — unsigned CHUID is a medium finding
5. `compliance` — note proprietary instruction usage

### User wants to identify a card

Focus on:
1. `card_identification` — name, vendor, confidence, signals
2. `token_identity` — serial, version, GUID
3. `atr` — ATR parse if available (protocol, convention, historical bytes)

### User asks about a specific exchange or error

Run with `--verbose` to get all annotations, then find the relevant exchange by ID and explain what the command did, what the card responded, and whether it indicates a problem.

### User asks about certificates

Focus on:
1. `cert_provisioning` — slot status
2. `object_ledger` — filter for 5FC1xx entries (PIV cert objects)
3. The dashboard embeds the PV certificate viewer (vendored @peculiar/certificates-viewer) for interactive X.509 inspection directly in the exchange detail and threat findings
4. Cert slot badges in the Findings tab are clickable and jump to the exchange with the PV viewer

## Log Format

The analyzer expects macOS CryptoTokenKit APDU log lines:

```
YYYY-MM-DD HH:MM:SS.nnn ... APDU -> xx xx xx ...   (command)
YYYY-MM-DD HH:MM:SS.nnn ... APDU <- xx xx xx ...   (response)
```

To capture on macOS:
```bash
log stream --predicate 'subsystem == "com.apple.CryptoTokenKit"' --level debug > trace.log
```

## Supported Card Families

| Family | ATR DB | AID | Serial | Version | CHUID |
|--------|--------|-----|--------|---------|-------|
| YubiKey (PIV) | yes | A000000527 | INS 0x01 | INS 0xFD | yes |
| SafeNet eToken/Fusion | yes | — | CLA 0x82 CA | DF30 | yes |
| Gemalto IDPrime | yes | A0000001520000 | — | — | yes |
| Generic PIV | — | A000000308 | — | — | yes |
| EMV payment | yes | A000000003/04 | — | — | — |
| Belgian eID | yes | — | — | — | — |
| JCOP / JavaCard | yes | — | — | — | — |
| GSM/USIM | yes | — | — | — | — |
| MIFARE DESFire | yes | — | — | — | — |
| Nitrokey HSM | yes | — | — | — | — |

5,100+ ATR entries, 44 AID patterns, 92 TLV tag definitions.

## Web UI

For interactive analysis with visual hex annotation, certificate viewing, and AI-powered exchange analysis, point users to:
https://peculiarventures.github.io/cardforensics/

The web UI and this skill use the same analysis engine.
