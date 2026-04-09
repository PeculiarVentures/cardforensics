---
name: cardforensics
description: Analyze smart card APDU traces for forensic investigation, security auditing, and provisioning debugging. Use this skill whenever the user uploads a macOS CryptoTokenKit log file (.log), mentions smart card APDU analysis, asks about PIV/GlobalPlatform card behavior, wants to debug smart card provisioning issues, or needs to identify a card from its APDU trace. Also use when the user mentions CardForensics, APDU forensics, eToken analysis, YubiKey trace analysis, or card provisioning debugging. This skill runs a full analysis pipeline covering card identification, token identity extraction, threat detection, default key brute-force, certificate provisioning checks, and security scoring.
---

# CardForensics Skill

Forensic analysis of PIV/GlobalPlatform smart card APDU traces. This skill wraps the [CardForensics](https://github.com/PeculiarVentures/cardforensics) analysis pipeline as a CLI tool.

## When to Use

- User uploads a `.log` file containing CryptoTokenKit APDU traces
- User asks to analyze smart card communication
- User is debugging PIV provisioning, SCP03 authentication, or card management
- User wants to identify an unknown smart card from its APDU traffic
- User asks about card security: default keys, credential exposure, nonce reuse

## How to Run

The analysis script is at `skill/scripts/analyze.js` in the CardForensics repo.

### Step 1: Clone the repo (if not already present)

```bash
cd /home/claude
git clone https://github.com/PeculiarVentures/cardforensics.git
cd cardforensics
npm install
```

### Step 2: Run the analyzer

```bash
cd /home/claude/cardforensics
npx vite-node skill/scripts/analyze.js <path-to-log-file> [--atr <hex>]
```

- `<path-to-log-file>` — the uploaded CryptoTokenKit `.log` file
- `--atr <hex>` — optional ATR hex string if known (improves card identification)

The script outputs structured JSON to stdout.

### Step 3: Interpret and present results

The JSON output contains these sections. Present them in natural language, focusing on what matters for the user's question.

#### Card Identification (`card_identification`)
- `name` — card family (e.g., "YubiKey (PIV)", "SafeNet eToken 5110")
- `vendor` — manufacturer
- `confidence` — identification confidence (0-100%)
- `signals` — evidence used for identification

#### Token Identity (`token_identity`)
- `serial` — hardware serial number
- `version` — firmware/applet version
- `chuid.guid` — PIV credential GUID (UUID format)
- `chuid.fascn` — Federal Agency Smart Credential Number (hex)
- `chuid.expiration` — credential expiration date
- `chuid.hasSignature` — whether the CHUID is signed

#### Security Score (`security_score`)
- `score` — 0-100, higher is better
- `label` — human-readable rating
- `breakdown` — per-category deductions

#### Threats (`threats`)
Each threat has `id`, `severity` (critical/high/medium/low), `title`, and `detail`.

Common findings:
- `default-mgmt-key` — card uses a known default management key
- `cleartext-credential` — PIN/PUK visible in plaintext
- `nonce-replay` — repeated challenge nonces (timing side-channel)
- `unsigned-chuid` — CHUID lacks issuer signature
- `unauth-cert-read` — certificates readable without authentication

#### Key Check (`key_check`)
- `pairs_tested` — number of key brute-force attempts
- `matches` — any default/known keys found (critical finding)

#### Certificate Provisioning (`cert_provisioning`)
- `probed` — PIV cert slots the host checked
- `populated` — slots with certificates
- `absent` — slots without certificates
- `required_populated` — whether mandatory PIV slots (9A, 9C, 9D, 9E) are filled

#### Trace Integrity (`integrity`)
- `kind` — complete, fragment, filtered, snippet
- `warnings` — any integrity issues detected

#### Notable Annotations (`notable_annotations`)
Exchanges flagged as `bug`, `warn`, or `key` (credential material observed).

## Presentation Guidelines

- Lead with the card identification and token identity — this is what the user usually wants first
- Highlight critical/high severity threats prominently
- If `key_check.matches` is non-empty, flag this as a critical finding (card uses default keys)
- For provisioning debugging, focus on cert_provisioning and notable_annotations with `bug` flags
- For security audits, lead with security_score and threats
- Quote specific exchange IDs when referencing notable_annotations so the user can cross-reference
- If the trace has integrity issues (fragment, filtered), note that analysis may be incomplete

## Supported Card Families

| Card Family | Serial | Version | CHUID |
|-------------|--------|---------|-------|
| YubiKey (PIV) | INS 0x01 | INS 0xFD | GET DATA 5FC102 |
| SafeNet eToken 5110/Fusion | CLA 0x82 CA | DF30 (P1/P2 or data) | GET DATA 5FC102 |
| Generic PIV | — | — | GET DATA 5FC102 |
| Gemalto IDPrime | — | — | GET DATA 5FC102 |
| EMV payment cards | — | — | — |
| JCOP / JavaCard | — | — | — |

Card identification uses a 5,100+ entry ATR database, AID matching, and CLA/tag heuristics.

## Log Format

The analyzer expects macOS CryptoTokenKit log format:
```
YYYY-MM-DD HH:MM:SS.nnn ... APDU -> xx xx xx ...   (command)
YYYY-MM-DD HH:MM:SS.nnn ... APDU <- xx xx xx ...   (response)
```

To capture these logs on macOS:
```bash
log stream --predicate 'subsystem == "com.apple.CryptoTokenKit"' --level debug > trace.log
```
