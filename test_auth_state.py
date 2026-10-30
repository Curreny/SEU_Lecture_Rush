"""认证缓存和回退流程的离线测试，不连接学校接口。"""

import json
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from auth_state import AuthState, business_session_valid, restore_cas_login

# 避免测试认证功能时加载 OCR 模型。
with patch.dict(sys.modules, {"ddddocr": SimpleNamespace(DdddOcr=Mock())}):
    import lecture_request as app


def response(payload=None, status=200, redirect=False):
    result = Mock(status_code=status, is_redirect=redirect)
    result.json.return_value = payload
    if status >= 400:
        result.raise_for_status.side_effect = requests.HTTPError(str(status))
    return result


class AuthStateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.state = AuthState("test-account", self.root)
        self.session = requests.Session()
        self.addCleanup(self.session.close)

    def test_restart_preserves_device_and_full_cookie_attributes(self):
        for domain, path, value in [
            ("auth.seu.edu.cn", "/auth", "cas-cookie"),
            ("ehall.seu.edu.cn", "/", "business-cookie"),
        ]:
            self.session.cookies.set(
                "JSESSIONID", value, domain=domain, path=path, secure=True,
                rest={"HttpOnly": None, "SameSite": "Lax"},
            )
        self.session.cookies.set("expired", "old", domain="auth.seu.edu.cn", expires=int(time.time()) - 10)
        self.state.remember_login({"tgtCookie": "test-token", "maxAge": -1})
        self.state.save(self.session)
        loaded = AuthState("test-account", self.root)
        restored = requests.Session()
        self.addCleanup(restored.close)
        loaded.restore(restored)
        self.assertEqual(loaded.data["fingerprint"], self.state.data["fingerprint"])
        self.assertEqual(loaded.data["vpn_device_id"], self.state.data["vpn_device_id"])
        self.assertEqual(loaded.data["tgt_cookie"], "test-token")
        self.assertEqual(restored.headers["User-Agent"], loaded.data["user_agent"])
        self.assertEqual(len(restored.cookies), 2)
        for cookie in self.session.cookies:
            if not cookie.is_expired():
                copy = next(c for c in restored.cookies if c.domain == cookie.domain)
                self.assertEqual(vars(cookie), vars(copy))
        self.assertEqual(stat.S_IMODE(self.state.path.stat().st_mode), 0o600)

    def test_account_isolation_and_corrupt_cache(self):
        self.state.save(self.session)
        other = AuthState("other-account", self.root)
        self.assertNotEqual(other.path, self.state.path)
        self.assertNotEqual(other.data["fingerprint"], self.state.data["fingerprint"])
        self.state.path.write_text("{broken", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "缓存损坏"):
            AuthState("test-account", self.root)

    def test_probe_rejects_login_page_and_anonymous_data(self):
        self.session.post = Mock(return_value=response({"code": 0, "datas": {"xsxxList": [{}]}}))
        self.assertTrue(business_session_valid(self.session))
        self.session.post.return_value = response({"code": 0, "datas": {"xsxxList": []}})
        self.assertFalse(business_session_valid(self.session))
        self.session.post.return_value = response(redirect=True)
        self.assertFalse(business_session_valid(self.session))
        self.session.post.return_value = response()
        self.session.post.return_value.json.side_effect = ValueError("HTML login page")
        self.assertFalse(business_session_valid(self.session))
        self.session.post.return_value = response(status=503)
        with self.assertRaises(requests.HTTPError):
            business_session_valid(self.session)

    def test_tgt_restoration_uses_saved_token_and_clears_rejected_token(self):
        self.state.data["tgt_cookie"] = "old-token"
        good = {"success": True, "code": 200, "redirectUrl": "fresh-callback", "tgtCookie": "new-token"}
        self.session.post = Mock(return_value=response(good))
        self.assertEqual(restore_cas_login(self.session, self.state), good)
        self.assertEqual(self.session.post.call_args.kwargs["json"]["tgtCookie"], "old-token")
        self.assertEqual(self.state.data["tgt_cookie"], "new-token")
        self.session.post.return_value = response({"success": False, "code": 400})
        self.assertIsNone(restore_cas_login(self.session, self.state))
        self.assertIsNone(self.state.data["tgt_cookie"])

    def test_tgt_http_rejection_falls_back_but_server_failure_does_not(self):
        for status in (401, 403):
            self.state.data["tgt_cookie"] = "old-token"
            self.session.post = Mock(return_value=response(status=status))
            self.assertIsNone(restore_cas_login(self.session, self.state))
            self.assertIsNone(self.state.data["tgt_cookie"])
        self.state.data["tgt_cookie"] = "old-token"
        self.session.post.return_value = response(status=503)
        with self.assertRaises(requests.HTTPError):
            restore_cas_login(self.session, self.state)
        self.assertEqual(self.state.data["tgt_cookie"], "old-token")

    def test_unavailable_restore_endpoint_preserves_token_and_device_trust(self):
        self.state.data["tgt_cookie"] = "possibly-valid-token"
        self.session.cookies.set("TRUST_DEVICE", "trusted-device", domain="auth.seu.edu.cn", path="/")
        fingerprint = self.state.data["fingerprint"]
        for status in (404, 405, 410):
            with self.subTest(status=status):
                self.session.post = Mock(return_value=response(status=status))
                self.assertIsNone(restore_cas_login(self.session, self.state))
                self.assertEqual(self.state.data["tgt_cookie"], "possibly-valid-token")
                self.assertEqual(self.state.data["fingerprint"], fingerprint)
                self.assertEqual(self.session.cookies.get("TRUST_DEVICE"), "trusted-device")

    def test_restore_endpoint_404_continues_through_normal_login(self):
        self.state.data["tgt_cookie"] = "saved-token"
        self.session.cookies.set("TRUST_DEVICE", "trusted-device", domain="auth.seu.edu.cn", path="/")
        self.session.post = Mock(return_value=response(status=404))

        def login_with_trust(session, state):
            self.assertIs(session, self.session)
            self.assertEqual(session.cookies.get("TRUST_DEVICE"), "trusted-device")
            self.assertEqual(state.data["fingerprint"], self.state.data["fingerprint"])
            return {"redirectUrl": "fresh-callback"}

        with patch.object(app, "business_session_valid", side_effect=[False, True]), \
                patch.object(app, "login", side_effect=login_with_trust) as login, \
                patch.object(app, "get_cookie1") as callback, \
                patch.object(app, "vpn_validation"), patch.object(app, "get_cookie2"):
            app.authenticate(self.session, self.state)
        login.assert_called_once_with(self.session, self.state)
        callback.assert_called_once_with(self.session, "fresh-callback")

    def test_sms_submission_reencrypts_both_inputs_with_new_key(self):
        challenge = {"success": False, "code": 502, "needStage2Validation": False}
        good = {"success": True, "code": 200, "redirectUrl": "fresh-callback", "tgtCookie": "test-token"}
        sent_bodies = []
        responses = iter([
            response(challenge),
            response({"success": True, "code": 200, "info": "验证码已发送"}),
            response(good),
        ])

        def post(url, **kwargs):
            sent_bodies.append((url, kwargs["json"].copy()))
            return next(responses)

        self.session.post = Mock(side_effect=post)
        with patch.object(app, "username", "test-account"), patch.object(app, "password", "original-password"), \
                patch.object(app, "getkey", side_effect=["K1", "K2"]), \
                patch.object(app, "rsa_encrypt_password", side_effect=lambda text, key: f"{text}:{key}") as encrypt, \
                patch("builtins.input", return_value=" 123456 "):
            self.assertEqual(app.login(self.session, self.state), good)
        self.assertEqual(sent_bodies[0][1]["password"], "original-password:K1")
        second = sent_bodies[2][1]
        self.assertEqual(second["password"], "original-password:K2")
        self.assertEqual(second["mobileVerifyCode"], "123456:K2")
        self.assertNotIn("stage2Code", second)
        self.assertTrue(second["rememberTrustDevice"])
        self.assertEqual(sent_bodies[0][1]["fingerPrint"], second["fingerPrint"])
        self.assertEqual(encrypt.call_count, 3)
        saved = json.loads(self.state.path.read_text())
        self.assertEqual(saved["tgt_cookie"], "test-token")
        for secret in ("original-password", "123456", "K1", "K2"):
            self.assertNotIn(secret, self.state.path.read_text())

    def test_sms_send_failure_does_not_prompt_or_submit_again(self):
        self.session.post = Mock(side_effect=[
            response({"code": 502, "success": False}),
            response({"code": 429, "success": False, "info": "请稍后再试"}),
        ])
        with patch.object(app, "password", "test-password"), patch.object(app, "getkey", return_value="K1"), \
                patch.object(app, "rsa_encrypt_password", return_value="cipher"), patch("builtins.input") as prompt:
            with self.assertRaisesRegex(RuntimeError, "短信发送失败"):
                app.login(self.session, self.state)
        prompt.assert_not_called()
        self.assertEqual(self.session.post.call_count, 2)

    def test_live_business_session_skips_cas_and_password(self):
        self.session.cookies.set("session", "test", domain="ehall.seu.edu.cn")
        with patch.object(app, "business_session_valid", return_value=True), \
                patch.object(app, "restore_cas_login") as restore, patch.object(app, "login") as login:
            app.authenticate(self.session, self.state)
        restore.assert_not_called()
        login.assert_not_called()

    def test_expired_business_and_cas_sessions_fall_back_to_login(self):
        self.session.cookies.set("session", "test", domain="ehall.seu.edu.cn")
        with patch.object(app, "business_session_valid", side_effect=[False, True]), \
                patch.object(app, "restore_cas_login", return_value=None), \
                patch.object(app, "login", return_value={"redirectUrl": "fresh-callback"}) as login, \
                patch.object(app, "get_cookie1", return_value="callback") as callback, \
                patch.object(app, "vpn_validation") as vpn, patch.object(app, "get_cookie2"):
            app.authenticate(self.session, self.state)
        login.assert_called_once_with(self.session, self.state)
        callback.assert_called_once_with(self.session, "fresh-callback")
        vpn.assert_called_once_with(self.session, "callback", self.state)

    def test_valid_cas_token_rebuilds_business_session_without_password(self):
        with patch.object(app, "business_session_valid", return_value=True), \
                patch.object(app, "restore_cas_login", return_value={"redirectUrl": "fresh-callback"}), \
                patch.object(app, "login") as login, patch.object(app, "get_cookie1"), \
                patch.object(app, "vpn_validation"), patch.object(app, "get_cookie2"):
            app.authenticate(self.session, self.state)
        login.assert_not_called()

    def test_rebuilt_but_invalid_business_session_stops(self):
        with patch.object(app, "business_session_valid", return_value=False), \
                patch.object(app, "restore_cas_login", return_value={"redirectUrl": "fresh-callback"}), \
                patch.object(app, "get_cookie1"), patch.object(app, "vpn_validation"), patch.object(app, "get_cookie2"):
            with self.assertRaisesRegex(RuntimeError, "停止预约"):
                app.authenticate(self.session, self.state)

    def test_existing_vpn_session_does_not_require_redirect_headers(self):
        self.session.get = Mock(side_effect=[response(), response(), response()])
        self.session.post = Mock(return_value=response({
            "success": True, "redirectUrl": "https://ehall.seu.edu.cn/callback?ticket=fresh",
        }))
        app.get_cookie2(self.session)
        self.assertEqual(self.session.get.call_count, 3)

    def test_auth_only_never_enters_reservation_loop(self):
        with patch.object(app, "username", "test-account"), \
                patch.object(app, "AuthState", return_value=self.state), \
                patch.object(app, "authenticate") as authenticate, \
                patch.object(app, "reserve_until_success") as reserve, \
                patch.object(sys, "argv", ["lecture_request.py", "--auth-only"]):
            app.main()
        authenticate.assert_called_once()
        reserve.assert_not_called()

    def test_python_rsa_round_trip_for_password_and_sms(self):
        import base64
        key = RSA.generate(1024)
        public = base64.urlsafe_b64encode(key.public_key().export_key(format="DER")).decode().rstrip("=")
        for plain in ("test-password", "123456"):
            cipher = app.rsa_encrypt_password(plain, public)
            actual = PKCS1_v1_5.new(key).decrypt(base64.b64decode(cipher), None)
            self.assertEqual(actual, plain.encode())


if __name__ == "__main__":
    unittest.main()
