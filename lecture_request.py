import base64
import argparse
import json
import re
from getpass import getpass
import secrets
import time
from pathlib import Path
import ddddocr
import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from urllib.parse import urlsplit, parse_qs, unquote
from datetime import datetime
import os
from dotenv import load_dotenv
# 与 main.py 一样复用识别器，避免每次获取验证码都重新加载模型。
ocr = ddddocr.DdddOcr(show_ad=False)

load_dotenv(override=True)  # 从 .env 文件加载环境变量，覆盖系统环境变量
WID = os.getenv("WID")
username = os.getenv("username")
password = os.getenv("password")
print(username)
print(password)
start_time = datetime(2026, 10, 26, 12, 26, 15) # "yyyy-mm-dd hh:mm:ss" 预约开始时间，必须严格按格式输入，否则会报错；到点才允许发commit_code请求
POLL_INTERVAL = 0 # 每轮结束后等待的秒数，可自行调整；Ctrl+C 停止。


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
    return session.post(getKey_url, headers=getkey_head, json={}).json()["publicKey"]

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
    login_response = session.post(login_url, headers=login_head, json=login_body)
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
    response = session.get(url, params={"redirectUrl": unquote(redirect_url)})
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
    config_response = session.get("https://vpn.seu.edu.cn/passport/v1/public/authConfig",params=params)
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
        reportEnv_response = session.post(reportEnv_url, json=reportEnv_body, params=params, headers={"X-Csrf-Token": csrfToken})
        reportEnv_response.raise_for_status()
        reportEnv_result = reportEnv_response.json()
        if reportEnv_result["code"] != 0:
            raise RuntimeError(f"浏览器环境上报失败：code={reportEnv_result['code']}")
        print("浏览器环境上报成功")

    # 3.authcheck
    authcheck_url = "https://vpn.seu.edu.cn/passport/v1/auth/authCheck"
    authcheck_response = session.get(authcheck_url, params=params)
    authcheck_response.raise_for_status()
    authcheck_result = authcheck_response.json()
    if authcheck_result["code"] != 0:
        raise RuntimeError(f"VPN 认证检查失败：code={authcheck_result['code']}")
    print("VPN 认证检查成功")


    return authcheck_result

def get_cookie2(session: requests.Session):
    """在 VPN 认证完成后取得业务入口并接收 Cookie；空 Cookie 和登录跳转均视为失败。"""
    # 步骤 1：从业务入口的实时重定向取得验证地址，保留服务器签发的完整 t。
    url = "https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do"
    response = session.get(url, allow_redirects=False)
    response.raise_for_status()
    location = response.headers["Location"]#拿到https://vpn.seu.edu.cn:443/controller/v1/public/verify?t=xxxxxxx的url地址

    # 步骤 2：验证成功后由服务器提供两个业务参数，不硬编码抓包中的值。
    verify_url = location
    verify_response = session.get(verify_url, allow_redirects=False)
    verify_response.raise_for_status()
    app_url = verify_response.headers["Location"] #拿到https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do?sdpAppCode=xxxx&unitId=xxxx

    # 步骤 3：访问验证后的入口，只有响应下发非空会话 Cookie 才算完成。
    app_response = session.get(app_url, allow_redirects=False) #直接请求这个app_url, 响应体里的set-cookie获得sdp_app_session-legacy-443和sdp_app_session-443
    app_response.raise_for_status()

    # 再发一次url的请求拿到route
    route_response = session.get(url, allow_redirects=False)
    route_response.raise_for_status()

    # 拿ticket_redirect_url
    ticket_url = "https://auth.seu.edu.cn/auth/casback/verifyTgt"
    ticket_body = {
        "service": "http://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do"
    }
    ticket_response = session.post(ticket_url, json=ticket_body)
    ticket_redirect_url = ticket_response.json()["redirectUrl"] # 拿到http://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do?ticket=ST-xxxxx

    # 向ticket_redirect_url请求，拿set-cookie:GS_SESSIONID
    # 同时重定向到http://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do，获取_WEU，更新JSESSIONID
    GS_response = session.get(ticket_redirect_url)
    
    return app_url


def appiontCheck(session: requests.Session):
    """打开预约按钮"""
    url = f"https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/modules/hdyy/appiontCheck.do?wid={WID}"
    response = session.get(url)

    return response.text


def get_code(session: requests.Session) -> str:
    """请求、解码并识别当前会话的新验证码；返回原始识别字符串，由预约循环校验格式。"""
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
    # 步骤 3：直接识别内存中的图片，不保存文件，也不猜改识别结果。
    captcha_text = ocr.classification(image_bytes)
    return image_bytes, captcha_text

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

def reserve_until_success(session: requests.Session):
    """复用登录会话循环预约，每轮获取新验证码；成功立即停止，异常直接报告。"""
    attempt = 0
    images_path = Path("captcha_images")
    images_path.mkdir(exist_ok=True)
    while True:
        attempt += 1
        # 步骤 1：沿用网页流程，先确认当前讲座允许预约。
        check = json.loads(appiontCheck(session))
        print(f"第 {attempt} 轮资格检查：{check}", flush=True)
        if str(check["code"]) == "0":
            # 步骤 2：当前会话获取新验证码后立即提交，不重复使用旧验证码。
            image_bytes, captcha_text = get_code(session)
            with open(images_path / f"captcha_{attempt}_{captcha_text}.jpg", "wb") as f:
                f.write(image_bytes)
            if re.fullmatch(r"[0-9]{4}", captcha_text) is None:
                print(f"第 {attempt} 轮验证码格式错误：{captcha_text!r}，跳过提交，重新检查预约资格", flush=True)
                time.sleep(POLL_INTERVAL)
                continue
            print(f"第 {attempt} 轮验证码格式正确：{captcha_text!r}，准备提交", flush=True)

            if datetime.now() > start_time: # 到点了才允许发commit_code请求
                result = json.loads(commit_code(session, captcha_text))
                print(f"第 {attempt} 轮提交结果：{result}", flush=True)
                # # 步骤 3：与网页一致，业务 code=0 且 datas=1 才确认预约成功。
                if str(result["code"]) == "0":
                    if str(result["datas"]) != "1":
                        raise RuntimeError(f"预约结果未确认成功：{result}")
                    print("预约成功，已停止轮询。", flush=True)
                    print("预约成功时间为", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    return result
        time.sleep(POLL_INTERVAL)


def main():
    """沿用同一会话完成 CAS、VPN 和业务认证；无论成功失败都关闭连接。"""
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0"
    # 公钥和登录必须沿用同一组 Cookie；响应下发的新 Cookie 由 Session 接收。
    
    try:
        result = login(session)
        print("CAS 登录成功")
        callback_response = get_cookie1(session, result["redirectUrl"])
        vpn_validation(session, callback_response)
        get_cookie2(session)
        
        # # print("会话 Cookie:",session.cookies.get_dict())  # 获取所有 Cookie 的字典形式
        reserve_until_success(session)
    except KeyboardInterrupt:
        print("已手动停止抢座。")
    finally:
        session.close()


if __name__ == "__main__":
    main()

