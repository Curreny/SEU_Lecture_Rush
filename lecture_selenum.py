"""
东南大学素质讲座预约抢票脚本
主要功能：自动登录系统、扫描符合要求的讲座并进行预约
"""

# ==================== 第三方库导入 ====================
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
import time
import base64
import ddddocr
import re
from datetime import datetime
import os
import platform
import traceback
from dotenv import load_dotenv

load_dotenv(override=True)  # 加载 .env 文件中的环境变量
# ==================== 全局配置项 ====================
CONFIG = {
    # 登录凭证
    "card_number": os.getenv("username"),
    "password": os.getenv("password"),
    # 讲座筛选条件
    "preferred_lectures": [],
    "required_categories": [
        # "人文与科学素养系列讲座_心理健康"
        # "人文与科学素养系列讲座_法律",
        "人文与科学素养系列讲座_艺术类",
        # "人文与科学素养系列讲座_其他"
    ],
    "allowed_campus": ["九龙湖校区"],  # 允许预约的线下校区
    "enable_offline": True, # 是否抢线下讲座
    "enable_online": True, # 是否抢线上讲座

    # ==================== 时间参数配置 ====================
    "timeout_settings": {
        "page_load": 0.5,  # 页面加载基础等待时间
        "element_wait": 3,  # 元素查找最大等待时间
        "login_redirect": 2,  # 登录跳转等待时间 # 浏览器未认证或掉认证时将此时常设定为较长时间(例如60s)，完成短信验证码认证后即可修改为正常值
        "scan_interval": 0.05,  # 扫描间隔时间
        "retry_delay": 0.05,  # 重试延迟时间
        "action_confirm": 0.2,  # 操作确认等待时间
    }
}

# ==================== 全局工具初始化 ====================
ocr = ddddocr.DdddOcr()

chrome_options = Options()
# chrome_options.add_argument("--headless")
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--window-size=1920x1080")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")

# ==================== 自动检测系统并配置 ChromeDriver ====================
def setup_driver():
    """根据操作系统自动配置 ChromeDriver"""
    system = platform.system().lower()

    # 检查当前目录下是否有 chromedriver
    possible_paths = []

    if system == "windows":
        possible_paths = [
            "./chromedriver.exe",
            "./chromedriver-win64/chromedriver.exe",
            "./chromedriver-windows/chromedriver.exe",
            "chromedriver.exe"
        ]
    elif system == "darwin":  # macOS
        possible_paths = [
            "./chromedriver",
            "./chromedriver-mac-arm64/chromedriver",
            "./chromedriver-mac-x64/chromedriver"
        ]
    else:  # linux
        possible_paths = [
            "./chromedriver",
            "./chromedriver-linux64/chromedriver"
        ]

    # 查找可用的 ChromeDriver
    chromedriver_path = None
    for path in possible_paths:
        if os.path.exists(path):
            chromedriver_path = path
            print(f"✅ 找到 ChromeDriver: {path}")
            break

    if chromedriver_path:
        service = Service(executable_path=chromedriver_path)
        return webdriver.Chrome(service=service, options=chrome_options)
    else:
        print("❌ 未找到 ChromeDriver，尝试自动下载或使用系统路径...")
        # 如果没找到，尝试使用系统 PATH 中的 ChromeDriver
        try:
            return webdriver.Chrome(options=chrome_options)
        except Exception as e:
            print(f"❌ 自动配置失败: {str(e)}")
            print("\n📝 请手动下载 ChromeDriver：")
            print("1. 访问 https://chromedriver.chromium.org/")
            print("2. 下载与您Chrome版本匹配的ChromeDriver")
            print("3. 解压后将chromedriver.exe放在脚本同目录下")
            exit(1)

# 初始化 driver
driver = setup_driver()

# ==================== 核心功能函数 ====================
def login():
    """执行系统登录操作 - 通用版本"""
    try:
        print("🌐 正在加载登录页面...")
        driver.get("https://ehall.seu.edu.cn/gsapp/sys/yddjzxxtjappseu/*default/index.do#/hdyy")
        time.sleep(CONFIG["timeout_settings"]["page_load"])  # 页面加载等待

        # 打印调试信息
        print(f"📄 当前页面标题: {driver.title}")
        print(f"🔗 当前页面URL: {driver.current_url}")

        # 尝试多种可能的选择器
        selectors_to_try = [
            # 统一认证页面选择器
            (By.ID, "username"),
            (By.NAME, "username"),
            (By.CSS_SELECTOR, "input[name='username']"),

            # 原登录页面选择器
            (By.CSS_SELECTOR, ".input-username-pc input"),
            (By.CSS_SELECTOR, "input[placeholder*='号']"),
            (By.CSS_SELECTOR, "input[type='text']"),
        ]

        username_input = None
        for by, selector in selectors_to_try:
            try:
                username_input = WebDriverWait(driver, CONFIG["timeout_settings"]["retry_delay"]).until(
                    EC.presence_of_element_located((by, selector))
                )
                print(f"✅ 找到用户名输入框: {by}={selector}")
                break
            except:
                continue

        if not username_input:
            print("❌ 无法找到用户名输入框")
            # 保存页面源码和截图以便调试
            with open("debug_page_source.html", "w", encoding="utf-8") as f:
                f.write(driver.page_source)
            driver.save_screenshot("debug_login.png")
            print("💾 已保存页面源码和截图到 debug_page_source.html 和 debug_login.png")
            return False

        # 清空并输入用户名
        username_input.clear()
        username_input.send_keys(CONFIG["card_number"])

        # 类似地查找密码输入框
        password_selectors = [
            (By.ID, "password"),
            (By.NAME, "password"),
            (By.CSS_SELECTOR, "input[type='password']"),
            (By.CSS_SELECTOR, ".input-password-pc input"),
        ]

        password_input = None
        for by, selector in password_selectors:
            try:
                password_input = driver.find_element(by, selector)
                print(f"✅ 找到密码输入框: {by}={selector}")
                break
            except:
                continue

        if not password_input:
            print("❌ 无法找到密码输入框")
            return False

        password_input.send_keys(CONFIG["password"])

        # 查找登录按钮
        button_selectors = [
            (By.CSS_SELECTOR, "button[type='submit']"),
            (By.CLASS_NAME, "login-button-pc"),
            (By.CSS_SELECTOR, "input[type='submit']"),
            (By.CSS_SELECTOR, "button"),
        ]

        login_button = None
        for by, selector in button_selectors:
            try:
                login_button = WebDriverWait(driver, CONFIG["timeout_settings"]["retry_delay"]).until(
                    EC.element_to_be_clickable((by, selector))
                )
                print(f"✅ 找到登录按钮: {by}={selector}")
                break
            except:
                continue

        if not login_button:
            print("❌ 无法找到登录按钮")
            return False

        login_button.click()
        print("✅ 登录信息已提交，等待页面跳转...")
        time.sleep(CONFIG["timeout_settings"]["login_redirect"])  # 登录跳转等待

        # 检查登录结果
        current_url = driver.current_url
        if "auth.seu.edu.cn" in current_url or "login" in current_url:
            print("❌ 登录失败，请检查账号密码")
            return False
        else:
            print("✅ 登录成功！")
            return True

    except Exception as e:
        print(f"❌ 登录过程中出错: {str(e)}")
        traceback.print_exc()
        # 保存页面源码和截图以便调试
        with open("error_page_source.html", "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        driver.save_screenshot("error_login.png")
        print("💾 已保存错误页面源码和截图到 error_page_source.html 和 error_login.png")
        return False

# ... 其余函数保持不变（is_time_conflict, parse_lecture, validate_lecture, reserve_lecture, lecture_scanner等）
def is_time_conflict(new_start, new_end, booked_lectures):
    """
    使用本轮已解析的预约记录检查时间冲突，不重复访问浏览器。

    Args:
        new_start: datetime 新讲座开始时间
        new_end: datetime 新讲座结束时间
        booked_lectures: list 本轮页面中已预约的讲座

    Returns:
        bool: True表示有时间冲突，False表示无冲突
    """
    for lecture in booked_lectures:
        if (new_start <= lecture["end_time"]) and (new_end >= lecture["start_time"]):
            return True
    return False

def _read_lecture_fields(elements):
    """
    一次浏览器调用读取本轮所有讲座字段；保留元素引用用于后续预约。
    使用页面渲染文本，要求原有选择器对应的字段存在；缺失时直接报错。
    """
    return driver.execute_script("""
        return arguments[0].map((element, index) => {
            // 缺失字段必须暴露，不能把未加载完整的卡片当作正常记录。
            const readText = (selector, position = 0) => {
                const node = element.querySelectorAll(selector)[position];
                if (!node) {
                    throw new Error(`第 ${index + 1} 场讲座缺少字段：${selector}[${position}]`);
                }
                return node.innerText.trim();
            };
            return {
                category: readText(".hdxq-hdlx .mint-text"),
                title: readText(".activity-name .mint-text"),
                location: readText("div[title='item.JZDD']"),
                time_text: readText(".activity-text .mint-text", 1),
                status: readText("button")
            };
        });
    """, elements)


def parse_lecture(element, fields):
    """
    解析本轮批量读取的讲座字段，不再逐字段访问浏览器。

    Args:
        element: WebElement 讲座页面元素
        fields: dict 与该元素对应的文本快照

    Returns:
        dict: 包含解析后的讲座信息，格式为：
            {
                "category": 讲座类别,
                "title": 讲座标题,
                "campus": 校区/线上,
                "start_time": 开始时间,
                "end_time": 结束时间,
                "element": 原始元素,
                "status": 预约状态
            }
    """
    try:
        # 解析基础信息
        category = fields["category"]
        title = fields["title"]
        location = fields["location"]

        # 解析时间信息
        time_text = fields["time_text"]
        time_matches = re.findall(r"\d{4}/\d{2}/\d{2}/\d{2}:\d{2}:\d{2}", time_text)
        start_time = datetime.strptime(time_matches[0], "%Y/%m/%d/%H:%M:%S")
        end_time = datetime.strptime(time_matches[1], "%Y/%m/%d/%H:%M:%S")

        return {
            "category": category,
            "title": title,
            "campus": _extract_campus(location),
            "start_time": start_time,
            "end_time": end_time,
            "element": element,
            "status": fields["status"]
        }
    except Exception as e:
        print(f"❌ 讲座解析失败: {str(e)}")
        traceback.print_exc()
        return None

def _extract_campus(location):
    """
    校区信息提取辅助函数

    Args:
        location: str 原始位置信息

    Returns:
        str: 提取后的校区/会议信息
    """
    campus_match = re.match(r'^(.+?校区)', location)
    return campus_match.group(1) if campus_match else location

def validate_lecture(lecture, booked_lectures):
    """保留布尔筛选接口；具体原因与扫描诊断共用同一套规则。"""
    return _lecture_rejection_reason(lecture, booked_lectures) is None


def _lecture_rejection_reason(lecture, booked_lectures):
    """
    验证讲座是否符合预约条件；线上按标题是否含“线上”判断。
    指定标题也必须通过其他筛选；时间冲突检查复用本轮快照。

    Args:
        lecture: dict 讲座信息字典
        booked_lectures: list 本轮页面中已预约的讲座

    Returns:
        str | None: 不符合条件的原因；None表示通过筛选
    """
    # 基础状态检查
    if lecture["status"] != "预约":
        return f"按钮状态不是“预约”：{lecture['status']!r}"

    # 指定标题只限制候选范围，不跳过校区和时间冲突检查
    if CONFIG["preferred_lectures"]:
        if lecture["title"] not in CONFIG["preferred_lectures"]:
            return "标题不在指定讲座列表中"

    # 类别检查
    if lecture["category"] not in CONFIG["required_categories"]:
        return f"类别不匹配：{lecture['category']!r}"

    # 线上不限制地点，线下必须属于配置的校区
    is_online = "线上" in lecture["title"]
    if not is_online and lecture["campus"] not in CONFIG["allowed_campus"]:
        return f"按标题判为线下，校区不在允许列表中：{lecture['campus']!r}"

    # 类型检查（线上/线下）
    if (is_online and not CONFIG["enable_online"]) or \
            (not is_online and not CONFIG["enable_offline"]):
        return "对应的线上或线下预约开关未开启"

    # 时间冲突检查
    if is_time_conflict(lecture["start_time"], lecture["end_time"], booked_lectures):
        return "与当前页面中的已预约讲座时间冲突"

    return None

def reserve_lecture(lecture):
    """
    执行讲座预约操作

    Args:
        lecture: dict 包含讲座信息的字典

    Returns:
        bool: True表示预约成功，False表示失败
    """
    max_retry = 3
    for attempt in range(max_retry):
        try:
            print(f"🔄 尝试预约: {lecture['title']} (尝试 {attempt + 1}/{max_retry})")

            # 点击预约按钮
            button = WebDriverWait(lecture["element"], CONFIG["timeout_settings"]["element_wait"]).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "button")))
            button.click()
            print("  已点击预约按钮...")

            # 处理验证码
            wait = WebDriverWait(driver, CONFIG["timeout_settings"]["element_wait"] // 2)
            vcode_img = wait.until(EC.presence_of_element_located((By.ID, "vcodeImg")))
            img_data = base64.b64decode(vcode_img.get_attribute("src").split("base64,")[1])

            # OCR识别
            captcha_text = ocr.classification(img_data)
            print(f"  验证码识别结果: {captcha_text}")

            # 输入验证码
            vcode_input = wait.until(EC.presence_of_element_located((By.ID, "vcodeInput")))
            vcode_input.clear()
            vcode_input.send_keys(captcha_text)

            # 点击确认
            confirm_btn = wait.until(EC.element_to_be_clickable((By.ID, "jqalert_yes_btn")))
            confirm_btn.click()

            # 等待结果
            time.sleep(CONFIG["timeout_settings"]["action_confirm"])

            # 检查是否成功（通过页面元素或URL变化判断）
            if "成功" in driver.page_source or "hdyy" not in driver.current_url:
                print(f"✅ 预约成功！ {lecture['title']}")
                return True
            else:
                print("  验证码错误或预约失败，重试...")
                # 关闭弹窗
                try:
                    close_btn = driver.find_element(By.CLASS_NAME, "mint-msgbox-btn")
                    close_btn.click()
                    time.sleep(CONFIG["timeout_settings"]["retry_delay"])
                except:
                    pass

        except Exception as e:
            print(f"  预约尝试 {attempt + 1} 失败: {str(e)}")

    print(f"❌ 预约失败，已达到最大重试次数: {lecture['title']}")
    return False

_last_scan_snapshot = None


def lecture_scanner():
    """
    刷新网页并扫描讲座；加载异常向外抛出，不伪装成没有候选。
    每轮打印统计，字段或筛选结果变化时打印详情并更新诊断快照。

    Returns:
        list: 按优先级排序后的可预约讲座列表
    """
    global _last_scan_snapshot
    # 第一步：刷新并等待讲座列表，分别记录导航和动态加载耗时。
    started_at = time.perf_counter()
    driver.refresh()
    refreshed_at = time.perf_counter()
    elements = WebDriverWait(
        driver, CONFIG["timeout_settings"]["element_wait"], poll_frequency=0.05
    ).until(EC.presence_of_all_elements_located((By.CLASS_NAME, "activity-container")))
    ready_at = time.perf_counter()

    # 第二步：批量读取并解析一次，避免每个候选都重新读取已预约记录。
    fields = _read_lecture_fields(elements)
    read_at = time.perf_counter()
    parsed_lectures = []
    parse_failures = 0
    for element, lecture_fields in zip(elements, fields):
        lecture = parse_lecture(element, lecture_fields)
        if lecture is None:
            parse_failures += 1
        else:
            parsed_lectures.append(lecture)
    booked_lectures = [lecture for lecture in parsed_lectures if lecture["status"] == "取消预约"]

    # 第三步：在同一份快照上筛选，保留原有诊断与优先级规则。
    valid_lectures = []
    diagnostics = []
    for lecture in parsed_lectures:
        reason = _lecture_rejection_reason(lecture, booked_lectures)
        diagnostics.append((lecture["title"], lecture["category"], lecture["campus"],
                            lecture["status"], lecture["start_time"], lecture["end_time"], reason))
        if reason is None:
            valid_lectures.append(lecture)

    filtered_at = time.perf_counter()
    print(f"📋 读取 {len(elements)} 场，解析失败 {parse_failures} 场，"
          f"符合条件 {len(valid_lectures)} 场，耗时 {filtered_at - started_at:.2f}s "
          f"（刷新 {refreshed_at - started_at:.2f}s，等待列表 {ready_at - refreshed_at:.2f}s，"
          f"读取 {read_at - ready_at:.2f}s，解析筛选 {filtered_at - read_at:.2f}s）", flush=True)
    snapshot = tuple(diagnostics)
    if snapshot != _last_scan_snapshot:
        print("📄 讲座列表或筛选结果变化：", flush=True)
        for title, category, campus, status, start, end, reason in diagnostics:
            print(f"  标题={title!r} | 类别={category!r} | 校区={campus!r} | "
                  f"状态={status!r} | 时间={start} 至 {end} | "
                  f"结果={reason if reason is not None else '通过筛选'}", flush=True)
        _last_scan_snapshot = snapshot

    # 按优先级排序
    return sorted(valid_lectures, key=_sort_priority)

def _sort_priority(lecture):
    """
    为已通过筛选的讲座生成排序键，不修改状态。
    线上优先于允许校区的线下场次，同类按开始时间升序排列。
    """
    is_online = "线上" in lecture["title"]
    return (0 if is_online else 1, lecture["start_time"])

# ==================== 主流程控制 ====================
def main_process():
    """主控制流程（支持多预约）"""
    no_lecture_reported = False  # 添加状态跟踪变量
    wait_dots = ['.  ', '.. ', '...']  # 等待动画符号
    wait_dot_index = 0
    scan_count = 0

    while True:
        try:
            scan_count += 1
            print(f"\n[{datetime.now():%Y-%m-%d %H:%M:%S}] 🔍 扫描次数: {scan_count}", flush=True)

            # 获取最新讲座列表
            lectures = lecture_scanner()
            if lectures:
                print(f"\n✅ 发现 {len(lectures)} 个符合条件的讲座")
                for i, lecture in enumerate(lectures[:3]):  # 只显示前3个
                    print(f"  {i + 1}. {lecture['title']}")

                # 尝试预约优先级最高的讲座
                if reserve_lecture(lectures[0]):
                    print("🎉 预约流程完成，程序退出")
                    break
                else:
                    print("🔄 预约失败，继续扫描...")
                    time.sleep(CONFIG["timeout_settings"]["retry_delay"])  # 失败后等待

            else:
                if not no_lecture_reported:
                    print("\n⏳ 未发现新讲座，持续扫描中", end="")
                    no_lecture_reported = True
                else:
                    print(f"\r⏳ 未发现新讲座，持续扫描中 {wait_dots[wait_dot_index]}", end="")
                    wait_dot_index = (wait_dot_index + 1) % len(wait_dots)

            time.sleep(CONFIG["timeout_settings"]["scan_interval"])  # 每次扫描间隔

        except Exception as e:
            no_lecture_reported = False
            print(f"\n‼ 发生异常: {str(e)}")
            traceback.print_exc()
            try:
                driver.refresh()
                time.sleep(CONFIG["timeout_settings"]["page_load"])
            except Exception:
                traceback.print_exc()
                print("❌ 页面刷新失败，尝试重新登录")
                if not login():
                    break

# ==================== 程序入口 ====================
if __name__ == "__main__":
    try:
        # 执行登录，检查是否成功
        if login():
            print("🚀 启动讲座扫描流程...")
            main_process()  # 启动主流程
        else:
            print("❌ 登录失败，程序退出")
    except KeyboardInterrupt:
        print("\n👋 用户中断程序")
    except Exception as e:
        print(f"\n❌ 程序异常: {str(e)}")
        traceback.print_exc()
    finally:
        driver.quit()
        print("🚗 浏览器已关闭")
