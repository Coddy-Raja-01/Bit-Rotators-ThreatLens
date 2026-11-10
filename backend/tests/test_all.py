import unittest
import sys
from pathlib import Path
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir))

from backend.scanners.ssrf import (
    validate_target_host,
    SSRFSecurityException,
    validate_url_for_scan,
    create_pinned_session,
)
from backend.scanners.lookalike import check_lookalike
from backend.scanners.certificate import (
    _chain_validation_result,
    _check_compromised_cas,
    _revocation_status,
)
from backend.scanners.intel import URLhausProvider
from backend.ai.provider import get_ai_mode_status
from backend.ai.scam_analyzer import analyze_scam_message
from backend.scanners.coordinator import execute_full_scan
from backend.ml.features import extract_features
from backend.ml.classifier import predict_phishing
from backend.scanners.scoring import calculate_unified_risk_score
from backend.database import (
    init_db, create_user, authenticate_user, 
    submit_community_report, vote_on_report, get_community_intel_for_domain,
    get_db
)
from backend.web3_service import (
    RegistryUnavailable,
    _registry,
    compute_report_hashes,
    get_registry_status,
    submit_report_commitment,
    verify_report_integrity,
)
from backend.main import (
    _create_session_token,
    _read_session_user_id,
    commit_report_integrity,
)

class ThreatLensTestSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_scan_history_table_is_removed(self):
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'scans'")
            self.assertIsNone(cursor.fetchone())
        finally:
            conn.close()

    # 1. SSRF Guard Tests
    def test_ssrf_loopback_blocked(self):
        with self.assertRaises(SSRFSecurityException):
            validate_target_host("127.0.0.1")

    def test_ssrf_localhost_blocked(self):
        with self.assertRaises(SSRFSecurityException):
            validate_target_host("localhost")

    def test_ssrf_cloud_metadata_blocked(self):
        with self.assertRaises(SSRFSecurityException):
            validate_target_host("169.254.169.254")

    def test_ssrf_private_network_blocked(self):
        with self.assertRaises(SSRFSecurityException):
            validate_target_host("192.168.1.1")

    def test_pinned_session_connects_to_validated_ip(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.headers["Host"].encode("ascii"))

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            hostname = "does-not-resolve.test"
            with create_pinned_session("127.0.0.1", hostname) as session:
                response = session.get(
                    f"http://{hostname}:{server.server_port}/",
                    timeout=2
                )
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.text, f"{hostname}:{server.server_port}")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_scan_skips_redirect_and_content_without_consent(self):
        url = "https://example.com/"
        with (
            patch("backend.scanners.coordinator.normalize_url_advanced", return_value={
                "normalized_url": url, "findings": []
            }),
            patch("backend.scanners.coordinator.validate_url_for_scan", return_value=(
                url, "example.com", ["93.184.216.34"], True
            )),
            patch("backend.scanners.coordinator.get_dns_characteristics", return_value={
                "findings": [], "records": {}
            }),
            patch("backend.scanners.coordinator.get_domain_rdap_registration", return_value={
                "findings": [], "registration_date": None
            }),
            patch("backend.scanners.coordinator.predict_phishing", return_value={
                "probability": 0.05, "engine": "test", "features": {}, "findings": []
            }),
            patch("backend.scanners.coordinator.check_lookalike", return_value={
                "is_lookalike": False, "findings": []
            }),
            patch("backend.scanners.coordinator.trace_redirects") as trace_redirects,
            patch("backend.scanners.coordinator.analyze_page_content") as analyze_content,
            patch("backend.scanners.coordinator.check_external_threat_intel", return_value={
                "findings": [], "intel_flagged": False
            }),
            patch("backend.scanners.coordinator.evaluate_headers_and_grade", return_value={
                "grade": "A", "score_numeric": 100, "findings": []
            }),
            patch("backend.scanners.coordinator.fingerprint_technology", return_value={
                "findings": [], "vulnerabilities": []
            }),
            patch("backend.scanners.coordinator.inspect_tls_certificate", return_value={
                "has_ssl": True, "findings": [], "weak_key_analysis": {"is_weak": False}
            }),
            patch("backend.scanners.coordinator.save_assessment"),
            patch("backend.scanners.coordinator.record_report_indicators"),
        ):
            report = execute_full_scan(url, authorized_target=False)

        trace_redirects.assert_not_called()
        analyze_content.assert_not_called()
        self.assertTrue(report["success"])
        self.assertFalse(report["target"]["authorized_target"])
        self.assertTrue(report["threat_analysis"]["redirects"]["skipped"])
        self.assertTrue(report["threat_analysis"]["content"]["skipped"])
        self.assertEqual(report["unified_scoring"]["coverage"]["skipped_checks"], 2)

    def test_report_hash_is_deterministic(self):
        report = {"target": {"hostname": "EXAMPLE.TEST"}, "unified_scoring": {"score": 5}}
        first_hashes = compute_report_hashes(report)
        self.assertEqual(first_hashes, compute_report_hashes(report))
        report["on_chain_commitment"] = {"tx_hash": "0x" + "1" * 64}
        self.assertEqual(first_hashes, compute_report_hashes(report))

    def test_chain_commitment_is_persisted_with_assessment(self):
        report = {
            "report_id": "proof-test",
            "target": {"normalized_url": "https://example.test", "hostname": "example.test"},
            "unified_scoring": {"classification": "Suspicious", "score": 30},
        }
        receipt = {"success": True, "chain_id": 31337, "tx_hash": "0x" + "1" * 64}
        with (
            patch("backend.main.get_assessment", return_value=report),
            patch("backend.main.submit_report_commitment", return_value=receipt),
            patch("backend.main.save_assessment") as save_report,
        ):
            result = commit_report_integrity("proof-test")

        self.assertEqual(result, receipt)
        persisted = save_report.call_args.kwargs["report_dict"]
        self.assertEqual(persisted["on_chain_commitment"], receipt)

    def test_session_token_is_signed_and_rejects_legacy_predictable_tokens(self):
        token = _create_session_token(42)
        self.assertEqual(_read_session_user_id(token), 42)
        self.assertIsNone(_read_session_user_id("42:sec_analyst"))
        self.assertIsNone(_read_session_user_id("42"))
        payload, signature = token.split(".", 1)
        tampered = f"{payload[:-1]}{'A' if payload[-1] != 'A' else 'B'}.{signature}"
        self.assertIsNone(_read_session_user_id(tampered))

    def test_session_token_expires(self):
        with patch("backend.main.time.time", return_value=1000):
            token = _create_session_token(42)
        with patch("backend.main.time.time", return_value=1000 + 12 * 60 * 60):
            self.assertIsNone(_read_session_user_id(token))

    def test_deployed_contract_commit_verify_revise(self):
        import uuid

        try:
            get_registry_status()
            web3, contract, _ = _registry()
        except RegistryUnavailable as exc:
            self.skipTest(f"Local ThreatRegistry is not available: {exc}")

        report = {
            "report_id": f"test-integrity-{uuid.uuid4().hex}",
            "target": {
                "hostname": "example.test",
                "input_url": "https://example.test/never-store-this-on-chain"
            },
            "unified_scoring": {"classification": "Low Risk", "score": 5}
        }
        receipt = submit_report_commitment(report)
        verified = verify_report_integrity(report)
        tampered = verify_report_integrity(report, simulated_tampering=True)

        self.assertEqual(receipt["contract_address"], contract.address)
        self.assertNotIn("never-store-this-on-chain", receipt["evidence_ref"])
        self.assertTrue(verified["verified"])
        self.assertFalse(tampered["verified"])

        old_hash, _ = compute_report_hashes(report)
        revised_report = {
            **report,
            "unified_scoring": {"classification": "Suspicious", "score": 26}
        }
        revised_hash, _ = compute_report_hashes(revised_report)
        contract.functions.reviseReport(
            receipt["on_chain_id"],
            bytes.fromhex(revised_hash[2:]),
            "Updated assessment evidence"
        ).transact({"from": receipt["reporter"]})
        self.assertFalse(contract.functions.verifyHash(bytes.fromhex(old_hash[2:])).call()[0])
        self.assertTrue(verify_report_integrity(revised_report)["verified"])

    # 2. Lookalike Domain Tests
    def test_lookalike_legitimate_brand(self):
        res = check_lookalike("paypal.com")
        self.assertTrue(res["is_legitimate_brand"])
        self.assertFalse(res["is_lookalike"])
        self.assertEqual(res["matched_brand"], "PayPal")

    def test_lookalike_does_not_flag_benign_example_domain(self):
        res = check_lookalike("example.com")
        self.assertFalse(res["is_lookalike"])

    def test_lookalike_does_not_match_single_character_brand_substrings(self):
        res = check_lookalike("example.com")
        self.assertNotEqual(res["matched_brand"], "Twitter / X")

    def test_judging_url_cases_have_three_suspicious_and_three_benign_examples(self):
        suspicious_urls = (
            "paypa1.com",
            "rnicrosoft-login.net",
            "chase-security-verify-auth.net",
        )
        benign_urls = ("example.com", "google.com", "github.com")

        for url in suspicious_urls:
            with self.subTest(url=url):
                self.assertTrue(check_lookalike(url)["is_lookalike"])
        for url in benign_urls:
            with self.subTest(url=url):
                result = check_lookalike(url)
                self.assertFalse(result["is_lookalike"])

    def test_urgency_alone_is_suspicious_not_confirmed_malicious(self):
        result = analyze_scam_message("Your account will be suspended within 24 hours.")
        self.assertEqual(result["classification"], "Suspicious")
        self.assertFalse(result["verified_fraud_evidence"])
        self.assertTrue(result["suspicious_language_signals"])

    def test_compromised_ca_catalog_ignores_non_distrust_disclosures(self):
        chain = [{"issuer": {"common_name": "eMudhra"}, "subject": {"common_name": "example.com"}}]
        with patch("backend.scanners.certificate.load_compromised_cas", return_value=[
            {"id": "CA-EMUDHRA", "ca_name": "eMudhra", "match_patterns": ["emudhra"], "distrusted": False}
        ]):
            self.assertEqual(_check_compromised_cas(chain), [])

    def test_revocation_is_not_reported_verified_without_a_query(self):
        result = _revocation_status({"is_expired": False, "ocsp_urls": ["http://ocsp.example.test"]})
        self.assertEqual(result["status"], "Not verified")
        self.assertIn("Revocation not verified", result["details"])

    def test_missing_issuer_is_not_mislabeled_as_invalid_certificate(self):
        error = type("VerificationError", (), {
            "verify_code": 20,
            "verify_message": "unable to get local issuer certificate",
        })()
        self.assertEqual(_chain_validation_result(error)[0], "Not verified")

    def test_urlhaus_without_auth_key_is_reported_unconfigured(self):
        with patch.dict("os.environ", {}, clear=True):
            result = URLhausProvider().check("https://example.test/", "example.test")
        self.assertFalse(result["configured"])
        self.assertEqual(result["status"], "Auth-Key not configured")

    def test_ai_mode_reports_deterministic_local_engine_by_default(self):
        with patch.dict("os.environ", {"USE_EXTERNAL_AI": "false"}, clear=True):
            self.assertEqual(get_ai_mode_status()["mode"], "local")

    def test_lookalike_glyph_substitution(self):
        res = check_lookalike("rnicrosoft-login.net")
        self.assertTrue(res["is_lookalike"])
        self.assertEqual(res["matched_brand"], "Microsoft")
        self.assertIn("Visual glyph substitution", res["technique"])

    def test_lookalike_typosquatting(self):
        res = check_lookalike("paypa1.com")
        self.assertTrue(res["is_lookalike"])
        self.assertEqual(res["matched_brand"], "PayPal")

    def test_lookalike_homoglyph_cyrillic(self):
        # Cyrillic small 'а' (U+0430)
        cyrillic_target = "p\u0430ypal.com"
        res = check_lookalike(cyrillic_target)
        self.assertTrue(res["is_lookalike"])
        self.assertEqual(res["matched_brand"], "PayPal")
        self.assertIn("Homoglyph", res["technique"])

    # 3. Machine Learning Features & Classifier
    def test_ml_features_extraction(self):
        url = "http://paypal-security-update-account.com/login"
        feat = extract_features(url)
        self.assertGreater(feat["url_length"], 20)
        self.assertGreater(feat["domain_entropy"], 2.0)
        self.assertGreaterEqual(feat["sensitive_word_count"], 2)

    def test_ml_classifier_prediction(self):
        phish_url = "http://chase-online-verify-auth.net/signin"
        res = predict_phishing(phish_url)
        self.assertIn("probability", res)
        self.assertGreater(res["probability"], 0.4)
        self.assertIn(res["engine"], ("random_forest", "heuristic_fallback"))

    # 4. Unified Risk Score Engine
    def test_unified_scoring_clean(self):
        threat_mod = {"ml_probability": 0.05, "lookalike": {"is_lookalike": False}}
        sec_mod = {"grade": "A"}
        cert_mod = {"has_ssl": True, "weak_key_analysis": {"is_weak": False}}
        comm_mod = {"report_count": 0, "is_verified": False}
        tech_fp = {"vulnerabilities": []}

        res = calculate_unified_risk_score(threat_mod, sec_mod, cert_mod, comm_mod, tech_fp)
        self.assertEqual(res["classification"], "Low Risk")
        self.assertIn("absence of known threats is not proof of safety", res["disclaimer"].lower())
        self.assertLessEqual(res["score"], 25)

    def test_unified_scoring_malicious(self):
        threat_mod = {
            "ml_probability": 0.95,
            "lookalike": {"is_lookalike": True, "matched_brand": "Chase", "technique": "Typosquatting"},
            "content": {"cross_domain_forms": [{"has_password": True}]}
        }
        sec_mod = {"grade": "F"}
        cert_mod = {"has_ssl": False, "weak_key_analysis": {"is_weak": True, "reasons": ["No TLS"]}}
        comm_mod = {"report_count": 5, "is_verified": True}
        tech_fp = {"vulnerabilities": [{"severity": "CRITICAL", "cve": "CVE-2021-41773"}]}

        res = calculate_unified_risk_score(threat_mod, sec_mod, cert_mod, comm_mod, tech_fp)
        self.assertEqual(res["classification"], "Confirmed Malicious")
        self.assertGreaterEqual(res["score"], 75)
        self.assertGreater(res["evidence_count"], 3)

    # 5. Database Community Verification Threshold
    def test_community_consensus_verification(self):
        import uuid
        unique_domain = f"test-phish-{uuid.uuid4().hex[:6]}.xyz"
        test_url = f"http://{unique_domain}/login"
        rep_id = submit_community_report(
            url=test_url,
            category="banking",
            description="Automated unit test threat submission",
            reporter_ip="198.51.100.99"
        )
        
        # Initially unverified (1 confirmation)
        intel = get_community_intel_for_domain(unique_domain)
        self.assertFalse(intel["is_verified"])

        # Add 2 more confirmations to reach net 3
        vote_on_report(rep_id, "198.51.100.100", "confirm")
        vote_on_report(rep_id, "198.51.100.101", "confirm")

        intel_after = get_community_intel_for_domain(unique_domain)
        self.assertTrue(intel_after["is_verified"])

if __name__ == "__main__":
    unittest.main()
