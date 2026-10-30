import base64
import argparse
import hashlib
import json
from functools import cache
from getpass import getpass
import secrets
import time
from pathlib import Path
import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from urllib.parse import urlsplit, parse_qs, unquote
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import signal
# 预约首次查表时再加载，复用认证的采集脚本不依赖已审核标签文件。
CAPTCHA_MAP_PATH = Path(__file__).resolve().parent / "captcha_hashes_labels.json"

load_dotenv(override=True)  # 从 .env 文件加载环境变量，覆盖系统环境变量
WID = os.getenv("WID")
username = os.getenv("username")
password = os.getenv("password")
start_time = datetime(2026, 10, 29, 19, 0, 0) # "yyyy-mm-dd hh:mm:ss" 预约开始时间，必须严格按格式输入，否则会报错；到点才允许发commit_code请求
PREPARE_SECONDS = 10  # 提前多少秒重新准备；不是服务端确认的验证码有效期。


def log_progress(message: str):
    """立即输出带毫秒时间戳的进度，避免缓冲导致终端看不到正在执行的步骤。"""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] {message}", flush=True)


def request_with_log(session: requests.Session, step: str, method: str, url: str, **kwargs):
    """记录认证与准备请求的开始、状态和耗时；请求参数和异常保持原样。"""
    log_progress(f"{step}：开始请求（{method}）")
    started = time.perf_counter()
    response = session.request(method, url, **kwargs)
    log_progress(
        f"{step}：收到响应，HTTP {response.status_code}，"
        f"耗时 {time.perf_counter() - started:.3f}s，自动跳转 {len(response.history)} 次"
    )
    return response


def rsa_encrypt_password(password: str, public_key: str) -> str:
    """使用接口的 URL-safe Base64 公钥加密密码，返回与网页一致的 Base64 密文。

    采用 PKCS#1 v1.5 填充；不修改外部状态，格式错误或密码过长时直接抛出异常。
    """
    # 步骤 1：补齐 Base64 填充，解码接口返回的 DER 公钥。
    key_der = base64.b64decode(public_key + "=" * (-len(public_key) % 4), altchars=b"-_", validate=True)
    key = RSA.import_key(key_der)
    # 步骤 2：按网页的 UTF-16 码元编码规则处理密码，兼容非 BMP 字符。
    utf16 = password.encode("utf-16-be", errors="surrogatepass")
    password_bytes = "".join(chr(int.from_bytes(utf16[i:i + 2], "big")) for i in range(0, len(utf16), 2)).encode("utf-8", errors="surrogatepass")
    encrypted = PKCS1_v1_5.new(key).encrypt(password_bytes)
    # 步骤 3：登录接口接收标准 Base64 密文，而非 URL-safe Base64。
    return base64.b64encode(encrypted).decode("ascii")

def getkey(session: requests.Session) -> str:
    getKey_url = "https://auth.seu.edu.cn/auth/casback/getChiperKey"
    getkey_head = {
        "Host": "auth.seu.edu.cn",
        "Origin": "https://auth.seu.edu.cn",
        "Referer": "https://auth.seu.edu.cn/dist/",
    }
    return request_with_log(session, "CAS：获取加密公钥", "POST", getKey_url, headers=getkey_head, json={}).json()["publicKey"]

def login(session: requests.Session):
    """执行一次 CAS 登录并保留会话；登录失败或要求二次认证时直接报告错误。"""
    public_key = getkey(session)
    encrypted_password = rsa_encrypt_password(password, public_key)
    login_url = "https://auth.seu.edu.cn/auth/casback/casLogin"
    login_head = {
        "Host": "auth.seu.edu.cn",
        "Origin": "https://auth.seu.edu.cn",
        "Referer": "https://auth.seu.edu.cn/dist/"
    }
    login_body = {
        "loginType": "account",
        "password": encrypted_password,
        "service": "https://vpn.seu.edu.cn:443/passport/v1/auth/cas?sfDomain=CAS-auth",
        "username": username,
    }
    login_response = request_with_log(session, "CAS：提交登录", "POST", login_url, headers=login_head, json=login_body)
    login_response.raise_for_status()
    result = login_response.json()
    if result.get("success") is not True or result.get("needStage2Validation"):
        raise RuntimeError(
            f"CAS 登录未完成：code={result.get('code')}，"
            f"info={result.get('info')}，二次认证={result.get('needStage2Validation')}"
        )
    return result


def get_cookie1(session: requests.Session, redirect_url: str):
    # set-cookie获取JSESSIONID
    """使用本次登录的回调地址建立 VPN 会话，返回含后续认证参数的响应。"""
    url = "https://auth.seu.edu.cn/auth/casback/loginRedirect"
    # 接口返回的地址已编码一次；先解码，再由 params 编码，避免百分号被重复编码。
    response = request_with_log(session, "VPN：访问 CAS 登录回调", "GET", url, params={"redirectUrl": unquote(redirect_url)})
    response.raise_for_status()
    return response

def vpn_validation(session: requests.Session, callback_response: requests.Response):
    # 1.保留 CAS 回调结果，取出本次环境上报的auth_ticket
    callback_url = callback_response.url
    callback_params = parse_qs(urlsplit(callback_url).query)
    if callback_params.get("source") != ["auth_cas"]:
        raise RuntimeError("当前响应不是预期的 CAS 回调")
    auth_ticket = json.loads(callback_params["data"][0])

    # 获取这次会话的 CSRF token
    params = {
        "clientType": "SDPBrowserClient",
        "platform": "Windows",
        "lang": "zh-CN",
        "mod": 1,
        "needTicket": 1
    }
    config_response = request_with_log(session, "VPN：获取认证配置", "GET", "https://vpn.seu.edu.cn/passport/v1/public/authConfig", params=params)
    config_response.raise_for_status()
    config_result = config_response.json()
    if config_result["code"] != 0:
        raise RuntimeError(f"获取配置失败：code={config_result['code']}")

    csrfToken = config_result["data"]["security"]["csrfToken"]

    # 2.提交reportEnv请求
    if auth_ticket.get("env",{}).get("need"):
        device_id = "00" + secrets.token_hex(32)
        reportEnv_url = "https://vpn.seu.edu.cn/controller/v1/public/reportEnv"
        reportEnv_body = {
            "ticket": auth_ticket["ticket"],
            "deviceId": device_id,
            "env": {
                "endpoint": {
                    "device_id": device_id,
                    "device": {"type": "browser"}
                }
            }
        }
        reportEnv_response = request_with_log(session, "VPN：上报浏览器环境", "POST", reportEnv_url, json=reportEnv_body, params=params, headers={"X-Csrf-Token": csrfToken})
        reportEnv_response.raise_for_status()
        reportEnv_result = reportEnv_response.json()
        if reportEnv_result["code"] != 0:
            raise RuntimeError(f"浏览器环境上报失败：code={reportEnv_result['code']}")
        log_progress("浏览器环境上报成功")

    # 3.authcheck
    authcheck_url = "https://vpn.seu.edu.cn/passport/v1/auth/authCheck"
    authcheck_response = request_with_log(session, "VPN：检查认证状态", "GET", authcheck_url, params=params)
    authcheck_response.raise_for_status()
    authcheck_result = authcheck_response.json()
    if authcheck_result["code"] != 0:
        raise RuntimeError(f"VPN 认证检查失败：code={authcheck_result['code']}")
    log_progress("VPN 认证检查成功")

    return authcheck_result

def get_cookie2(session: requests.Session):
    """在 VPN 认证完成后取得业务入口并接收 Cookie；空 Cookie 和登录跳转均视为失败。"""
    # 步骤 1：从业务入口的实时重定向取得验证地址，保留服务器签发的完整 t。
    url = "https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do"
    response = request_with_log(session, "业务认证 1/6：访问讲座入口，获取验证地址", "GET", url, allow_redirects=False)
    response.raise_for_status()
    location = response.headers["Location"]#拿到https://vpn.seu.edu.cn:443/controller/v1/public/verify?t=xxxxxxx的url地址

    # 步骤 2：验证成功后由服务器提供两个业务参数，不硬编码抓包中的值。
    verify_url = location
    verify_response = request_with_log(session, "业务认证 2/6：验证 VPN 业务访问权限", "GET", verify_url, allow_redirects=False)
    verify_response.raise_for_status()
    app_url = verify_response.headers["Location"] #拿到https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do?sdpAppCode=xxxx&unitId=xxxx

    # 步骤 3：访问验证后的入口，只有响应下发非空会话 Cookie 才算完成。
    app_response = request_with_log(session, "业务认证 3/6：访问验证后的入口，接收业务 Cookie", "GET", app_url, allow_redirects=False) #直接请求这个app_url, 响应体里的set-cookie获得sdp_app_session-legacy-443和sdp_app_session-443
    app_response.raise_for_status()

    # 再发一次url的请求拿到route
    route_response = request_with_log(session, "业务认证 4/6：再次访问入口，获取路由 Cookie", "GET", url, allow_redirects=False)
    route_response.raise_for_status()

    # 拿ticket_redirect_url
    ticket_url = "https://auth.seu.edu.cn/auth/casback/verifyTgt"
    ticket_body = {
        "service": "http://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do"
    }
    ticket_response = request_with_log(session, "业务认证 5/6：verifyTgt 获取业务 Ticket", "POST", ticket_url, json=ticket_body)
    ticket_redirect_url = ticket_response.json()["redirectUrl"] # 拿到http://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do?ticket=ST-xxxxx

    # 向ticket_redirect_url请求，拿set-cookie:GS_SESSIONID
    # 同时重定向到http://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do，获取_WEU，更新JSESSIONID
    GS_response = request_with_log(session, "业务认证 6/6：访问 Ticket 回调并跟随跳转", "GET", ticket_redirect_url)
    
    return app_url


def appiontCheck(session: requests.Session):
    """打开预约按钮"""
    url = f"https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/modules/hdyy/appiontCheck.do?wid={WID}"
    response = session.get(url)

    return response.text


@cache
def load_captcha_map() -> dict[str, str]:
    """首次预约查表时读取并缓存已审核标签；文件缺失或格式错误直接抛出。"""
    with CAPTCHA_MAP_PATH.open(encoding="utf-8") as captcha_map_file:
        return json.load(captcha_map_file)

def get_code(session: requests.Session) -> str:
    """请求当前会话的新验证码，按图片字节的 SHA-256 返回已审核标签；未收录时直接抛错。"""
    # 步骤 1：请求新验证码，并检查接口是否成功。
    time_stamp = int(time.time() * 1000)
    url = f"https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/modules/hdyy/vcode.do"
    response = session.get(url, params={"_": time_stamp})
    response.raise_for_status()
    result = response.json()
    if result["code"] != 0:
        raise RuntimeError(f"验证码获取失败：code={result['code']}，msg={result.get('msg')}")
    data_url = result["datas"]
    # 步骤 2：直接解码图片字节，省去本地文件读写。
    image_bytes = base64.b64decode(data_url.split(",", 1)[1], validate=True)
    # 步骤 3：直接查找真实标签。
    return load_captcha_map()[hashlib.sha256(image_bytes).hexdigest()]

def commit_code(session: requests.Session, captcha_text):
    """沿用获取验证码的会话，以网页相同的表单格式提交预约；会实际创建预约。"""
    url = "https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/modules/hdyy/addReservation.do"
    body = {
        "wid": WID,
        "vcode": captcha_text
    }
    response = session.post(url, data=body)
    response.raise_for_status()
    return response.text

# def get_reserve_num(session: requests.Session):
#     """获取当前预约人数"""
#     url = "https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/modules/hdyy/getActivityDetail.do"
#     body = {
#         "wid": WID
#     }
#     response = session.post(url, data=body)
#     response.raise_for_status()
#     result = response.json()
#     YYRS = int(result["datas"]["hdxq"]["YYRS"])
#     HDZRS = int(result["datas"]["hdxq"]["HDZRS"])

#     return YYRS, HDZRS


def wait_until_start():
    """按本机时间等待开放，不发送网络请求；每次唤醒重新检查，防止提前提交。"""
    while True:
        remaining = (start_time - datetime.now()).total_seconds()
        if remaining <= 0:
            return
        time.sleep(remaining)


def reserve_until_success(session: requests.Session):
    """早期连续轮询，进入准备窗口后重新取码并等待提交；失败重新准备，异常直接抛出。"""
    prepare_at = start_time - timedelta(seconds=PREPARE_SECONDS)
    log_progress(
        f"开始无间隔轮询，WID={WID}，重新准备时间={prepare_at:%Y-%m-%d %H:%M:%S}，"
        f"提交开始时间={start_time:%Y-%m-%d %H:%M:%S}"
    )
    
    attempt = 0
    while True:
        attempt += 1
        started = time.perf_counter()
        # 步骤 1：以请求开始前的时间区分阶段，不沿用准备窗口之前发起的资格检查。
        preparing = datetime.now() >= prepare_at
        check = json.loads(appiontCheck(session))
        check_finished = time.perf_counter()
        if str(check["code"]) == "0":
            if not preparing and datetime.now() >= prepare_at:
                log_progress(
                    f"第 {attempt} 轮｜资格检查 {check_finished - started:.3f}s｜"
                    "已进入准备窗口，下一轮重新检查资格并取码"
                )
                continue
            # 步骤 2：重新取码；早期轮询所得验证码不用于最终提交。
            captcha_text = get_code(session)
            code_finished = time.perf_counter()
            if not preparing:
                log_progress(
                    f"第 {attempt} 轮｜早期轮询完成｜资格检查 {check_finished - started:.3f}s｜"
                    f"验证码请求及查表 {code_finished - check_finished:.3f}s｜"
                    f"总耗时 {code_finished - started:.3f}s｜"
                    f"距重新准备 {(prepare_at - datetime.now()).total_seconds():.3f}s"
                )
                continue
            log_progress(
                f"第 {attempt} 轮｜准备就绪｜资格检查 {check_finished - started:.3f}s｜"
                f"验证码请求及查表 {code_finished - check_finished:.3f}s｜"
                f"距提交时间 {(start_time - datetime.now()).total_seconds():.3f}s；停止刷新，等待提交"
            )
            # 步骤 3：等待期间保留本轮会话和验证码，到点后直接提交，不再插入前置请求。
            wait_until_start()
            submitted_at = datetime.now()
            submit_started = time.perf_counter()
            result = json.loads(commit_code(session, captcha_text))
            submit_elapsed = time.perf_counter() - submit_started
            success = str(result["code"]) == "0" and str(result["datas"]) == "1"
            log_progress(
                f"第 {attempt} 轮｜{'预约成功' if success else '提交结果'}：{result.get('msg', '')}"
                f"（code={result['code']}，datas={result.get('datas')}）｜"
                f"提交调用时间 {submitted_at:%Y-%m-%d %H:%M:%S.%f}｜"
                f"距开放 {(submitted_at - start_time).total_seconds():.3f}s｜"
                f"提交及解析耗时 {submit_elapsed:.3f}s"
            )
            # 步骤 4：确认成功后退出；业务失败重新检查资格并取码，不复用已提交的验证码。
            if success:
                return result
        else:
            log_progress(
                f"第 {attempt} 轮｜资格未通过：{check.get('msg', '')}（code={check['code']}）"
                f"｜耗时 {time.perf_counter() - started:.3f}s"
            )


def main():
    """认证一次后进入预约循环；异常向外抛出，成功、异常或 Ctrl+C 退出时均关闭连接。"""
    try:
        with requests.Session() as session:
            session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0"
            log_progress("开始 CAS 登录认证")
            result = login(session)
            log_progress("CAS 登录成功")
            callback_response = get_cookie1(session, result["redirectUrl"])
            vpn_validation(session, callback_response)
            log_progress("开始建立讲座业务会话（get_cookie2，共 6 步）")
            get_cookie2(session)
            log_progress("业务认证流程已返回，即将进入预约循环")
            reserve_until_success(session)
    except KeyboardInterrupt:
        log_progress("已手动停止抢座。")


if __name__ == "__main__":
    main()

