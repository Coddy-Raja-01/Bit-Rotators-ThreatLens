# TLS and Certificate Authority Trust Realities

## 1. The Green Padlock Misconception
A green padlock or active HTTPS protocol indicates exclusively that traffic between the client browser and the host is encrypted using TLS. It does NOT validate that the entity operating the server is reputable, legitimate, or safe. Over 80% of active phishing websites obtain free, automated Domain Validation (DV) certificates from providers like Let's Encrypt or ZeroSSL.

## 2. Certificate Transparency (CT) Logging
Certificate Transparency requires CAs to publicly log every issued certificate in cryptographically verifiable, append-only Merkle trees. Monitoring CT logs allows brand owners to discover rogue certificates or unauthorized subdomain issuances within hours of generation.

## 3. Cryptographic Key Weaknesses (eMudhra Incident)
Between 2022 and 2023, public audits revealed that certain automated batch enrollments by eMudhra CA in India suffered from pseudo-random number generator flaws that resulted in shared prime factors in generated RSA moduli. ThreatLens inspects key sizes, signature hash algorithms, and references known CA incident catalogs.

