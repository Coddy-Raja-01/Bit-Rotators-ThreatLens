# Phishing Indicators and Structural Signals

## 1. Domain Structure and Homoglyphs
Phishing actors utilize Cyrillic or Greek characters (IDN homoglyphs) that appear identical to Latin characters in web browsers (e.g., Cyrillic 'а' U+0430 mimicking Latin 'a' U+0061). Typosquatting leverages multi-character visual substitutions (e.g., 'rn' for 'm', 'vv' for 'w', 'cl' for 'd') or keyword prefix/suffixes (e.g., 'chase-security-login.com').

## 2. Insecure Form Submissions and Credential Harvesting
Legitimate login forms submit authentication requests to the same origin or an authorized identity provider on a recognized subdomain. Phishing pages frequently submit `<form action="...">` payloads across domains to attacker-controlled collector APIs, webhook listeners, or free cloud database endpoints.

## 3. Protocol Downgrade and Redirect Hopping
Attackers chain multiple redirect hops across different registrars and top-level domains to evade static URL scanners. Insecure redirects that transition from HTTPS back to HTTP strip encryption, exposing session tokens and credentials to network-level interception.

## 4. Script Obfuscation and Anti-Analysis
Malicious landing pages frequently obscure HTML source code using hexadecimal escape sequences (`\x65\x76\x61\x6c`), automated packers (e.g., `_0x` obfuscator signatures), or dynamic payload assembly via `String.fromCharCode` to hide credential harvesting forms from non-browser automated crawlers.

