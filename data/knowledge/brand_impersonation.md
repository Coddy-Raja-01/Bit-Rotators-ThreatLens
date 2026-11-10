# Brand Impersonation and Visual Deception Patterns

## 1. Title and Favicon Discrepancy
Attackers clone genuine corporate logos, favicons, and HTML `<title>` tags (e.g., "PayPal: Summary", "Microsoft Online Login") onto unrelated, newly registered domains. Comparing declared HTML page titles and brand identity against the authoritative domain registration is an effective automated signal.

## 2. PII Exfiltration Channels
Modern fraud campaigns direct victim payments through decentralized or peer-to-peer mechanisms to hinder chargebacks:
- Unified Payments Interface (UPI) handles in India
- Direct cryptocurrency addresses (BTC, ETH, SOL)
- Digital prepaid cards and gift vouchers

## 3. Threat Intelligence Consensus
Authoritative feeds such as URLhaus (abuse.ch), OpenPhish, and Google Safe Browsing verify malicious URLs through continuous honeypot capture, community analysis, and telemetry. High vendor consensus (>3 engines) provides deterministic confirmation of malicious intent.

