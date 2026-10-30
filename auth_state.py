"""按账号保存设备身份和会话；不保存密码、短信验证码或 RSA 密文。"""

import hashlib
import json
import os
import secrets
import tempfile
from http.cookiejar import Cookie
from pathlib import Path

import requests


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0"
)
AUTH_HEADERS = {
    "Origin": "https://auth.seu.edu.cn",
    "Referer": "https://auth.seu.edu.cn/dist/",
}
CAS_SERVICE = "https://vpn.seu.edu.cn:443/passport/v1/auth/cas?sfDomain=CAS-auth"
REQUEST_TIMEOUT = 20


class AuthState:
    def __init__(self, account: str, directory: Path | None = None):
        if not account:
            raise ValueError("请先在 .env 中配置 username")
        directory = directory if directory is not None else Path(__file__).parent / ".auth_state"
        self.path = directory / (hashlib.sha256(account.encode()).hexdigest() + ".json")
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
                if self.data["version"] != 1 or self.data["account"] != account:
                    raise ValueError("认证缓存版本或账号不匹配")
                for field in ("fingerprint", "vpn_device_id", "user_agent"):
                    if not isinstance(self.data[field], str) or not self.data[field]:
                        raise ValueError(f"认证缓存缺少 {field}")
                if not isinstance(self.data["cookies"], list):
                    raise ValueError("Cookie 缓存格式错误")
            except (ValueError, KeyError, TypeError) as exc:
                raise RuntimeError(f"认证缓存损坏：{self.path}；请移走该文件后重新认证") from exc
        else:
            self.data = {
                "version": 1,
                "account": account,
                # 此脚本自己的持久设备标识，不冒充已有浏览器的指纹。
                # 是否接受、记住该标识，由服务端在短信认证后决定。
                "fingerprint": "script_" + secrets.token_hex(16),
                "vpn_device_id": "00" + secrets.token_hex(32),
                "user_agent": DEFAULT_USER_AGENT,
                "tgt_cookie": None,
                "cookies": [],
            }

    def restore(self, session: requests.Session):
        session.headers["User-Agent"] = self.data["user_agent"]
        try:
            cookies = [Cookie(**item) for item in self.data["cookies"]]
        except (TypeError, ValueError, KeyError) as exc:
            raise RuntimeError(f"Cookie 缓存损坏：{self.path}") from exc
        for cookie in cookies:
            if not cookie.is_expired():
                session.cookies.set_cookie(cookie)

    def remember_login(self, result: dict):
        if result.get("tgtCookie"):
            self.data["tgt_cookie"] = result["tgtCookie"]
            # maxAge=-1 不表示永不过期；保存原值，实际有效性由服务器检查。
            self.data["tgt_max_age"] = result.get("maxAge")

    def save(self, session: requests.Session):
        cookies = []
        for cookie in session.cookies:
            if cookie.is_expired():
                continue
            item = vars(cookie).copy()
            item["rest"] = item.pop("_rest")
            cookies.append(item)
        self.data["cookies"] = cookies
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".auth-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.data, stream, ensure_ascii=False, indent=2)
            # mkstemp 创建的文件仅当前用户可读写；原子替换避免写一半的缓存。
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def business_session_valid(session: requests.Session) -> bool:
    """只读查询讲座列表，并确认返回个人信息；不调用预约或验证码接口。"""
    response = session.post(
        "https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/modules/hdyy/queryActivityList.do",
        allow_redirects=False,
        timeout=REQUEST_TIMEOUT,
    )
    if response.is_redirect or response.status_code in (401, 403):
        return False
    # 网络故障/服务端故障直接报告，不误判成需要发送短信。
    response.raise_for_status()
    try:
        result = response.json()
    except ValueError:
        return False
    if not isinstance(result, dict) or str(result.get("code")) != "0":
        return False
    data = result.get("datas")
    return isinstance(data, dict) and isinstance(data.get("xsxxList"), list) and bool(data["xsxxList"])


def restore_cas_login(session: requests.Session, state: AuthState) -> dict | None:
    """尝试 CAS 凭据恢复；旧接口不可用时回退，不重放旧 ST。"""
    token = state.data.get("tgt_cookie")
    if not token:
        return None
    response = session.post(
        "https://auth.seu.edu.cn/auth/casback/casLoginByCookie",
        headers=AUTH_HEADERS,
        json={"service": CAS_SERVICE, "tgtCookie": token},
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code in (404, 405, 410):
        # 打包前端中存在该接口，并不保证当前部署仍提供它。
        # 接口不可用不能证明凭据过期；保留 TGT、TRUST_DEVICE 和设备身份。
        print(f"CAS 凭据恢复接口不可用（HTTP {response.status_code}），将保留设备信任并重新登录。")
        return None
    if response.status_code in (401, 403):
        state.data["tgt_cookie"] = None
        return None
    response.raise_for_status()
    try:
        result = response.json()
    except ValueError:
        state.data["tgt_cookie"] = None
        return None
    if (
        isinstance(result, dict)
        and result.get("success") is True
        and str(result.get("code")) in ("200", "201")
        and result.get("redirectUrl")
    ):
        state.remember_login(result)
        return result
    state.data["tgt_cookie"] = None
    return None
