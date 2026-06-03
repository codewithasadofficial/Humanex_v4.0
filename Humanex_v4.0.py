import sys
import time
import random
import threading
import os
import uuid
import platform
import requests
import json
import traceback
import queue
import tempfile
import subprocess

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit, QMessageBox, QComboBox,
    QProgressBar, QTableWidget, QHeaderView, QAbstractItemView, QCheckBox, QSizePolicy
)
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import Qt, QTimer, pyqtSignal

from playwright.sync_api import sync_playwright

def set_playwright_env():
    import shutil
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
        temp_dir = tempfile.mkdtemp()
        playwright_src = os.path.join(base_path, "ms-playwright")
        playwright_dst = os.path.join(temp_dir, "ms-playwright")
        try:
            if not os.path.exists(playwright_dst):
                shutil.copytree(playwright_src, playwright_dst)
        except Exception as e:
            print("Error copying ms-playwright:", e)
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = playwright_dst
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = os.path.join(base_path, "ms-playwright")
    os.environ["PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD"] = "1"

set_playwright_env()

APP_NAME = "Humanex"
APP_VERSION = "v4.0"

UPDATE_VERSION_URL = "https://adsenseloadingmethod.com/humanex/version.txt"
UPDATE_EXE_URL = "https://adsenseloadingmethod.com/humanex/Humanex_v4.0.exe"

stop_event = threading.Event()

def log_emit(log_signal, msg):
    if log_signal:
        log_signal.emit(msg)
    else:
        print(msg)

class LicenseWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Activate {APP_NAME} {APP_VERSION}")
        self.setWindowIcon(QIcon("favicon.ico"))
        self.setGeometry(600, 300, 400, 160)
        self.setStyleSheet("background-color: #1b1e1f; color: white; font-family: monospace;")
        layout = QVBoxLayout()
        label = QLabel("🔐 Enter your license key:")
        label.setStyleSheet("font-size: 14px;")
        self.input = QLineEdit()
        self.input.setPlaceholderText("e.g. ASAD-2025-PRO")
        self.button = QPushButton("Activate")
        self.button.clicked.connect(self.check_key)
        self.message = QLabel("")
        self.message.setStyleSheet("color: red; font-size: 12px;")
        layout.addWidget(label)
        layout.addWidget(self.input)
        layout.addWidget(self.button)
        layout.addWidget(self.message)
        self.setLayout(layout)
        self.verified = False
        self.license_key = None

    def get_device_id(self):
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, platform.node()))

    def check_key(self):
        license_key = self.input.text().strip()
        device_id = self.get_device_id()
        user_agent = platform.platform()
        try:
            res = requests.post(
                "https://adsenseloadingmethod.com/license_system/check_license.php",
                data={"license_key": license_key, "device_id": device_id, "user_agent": user_agent},
                timeout=10
            )
            result = res.json()
            if result.get("status") == "valid":
                self.message.setStyleSheet("color: #3fcf4b; font-size: 13px;")
                self.message.setText("✅ License verified. Welcome!")
                self.verified = True
                self.license_key = license_key
                QTimer.singleShot(1200, self.accept_access)
            else:
                self.message.setStyleSheet("color: red; font-size: 12px;")
                self.message.setText("❌ " + result.get("message", "Invalid license."))
        except Exception as e:
            self.message.setStyleSheet("color: orange; font-size: 12px;")
            self.message.setText(f"⚠️ Cannot connect to license server.\n{e}")

    def accept_access(self):
        self.close()

def parse_proxy(proxy_line):
    parts = proxy_line.strip().split(":")
    if len(parts) == 4:
        host, port, user, pwd = parts
        return {"server": f"http://{host}:{port}", "username": user, "password": pwd}
    elif len(parts) == 2:
        host, port = parts
        return {"server": f"http://{host}:{port}", "username": None, "password": None}
    return None

def parse_netscape_cookies(txt):
    cookies = []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split('\t')
        if len(parts) < 7:
            continue
        domain, flag, path, secure, expires, name, value = parts
        cookies.append({
            "domain": domain,
            "path": path,
            "secure": secure.upper() == "TRUE",
            "expires": int(expires) if expires.isdigit() else None,
            "name": name,
            "value": value
        })
    return cookies

def normalize_cookies(cookies_raw):
    cookies = []
    if isinstance(cookies_raw, dict):
        if "cookies" in cookies_raw:
            cookies_raw = cookies_raw["cookies"]
        else:
            cookies_raw = [cookies_raw]
    if not isinstance(cookies_raw, list):
        return []
    for c in cookies_raw:
        if not isinstance(c, dict):
            continue
        cookie = {}
        cookie["name"] = c.get("name")
        cookie["value"] = c.get("value")
        cookie["domain"] = c.get("domain", c.get("host", c.get("domain_key", "")))
        cookie["path"] = c.get("path", "/")
        if "expires" in c:
            try:
                cookie["expires"] = int(c["expires"])
            except Exception:
                pass
        elif "expirationDate" in c:
            try:
                cookie["expires"] = int(c["expirationDate"])
            except Exception:
                pass
        cookie["secure"] = bool(c.get("secure", False))
        cookie["httpOnly"] = bool(c.get("httpOnly", c.get("http_only", False)))
        same_site_raw = c.get("sameSite", c.get("same_site", None))
        if same_site_raw:
            s = str(same_site_raw).strip().lower()
            if s in ["lax"]:
                cookie["sameSite"] = "Lax"
            elif s in ["strict"]:
                cookie["sameSite"] = "Strict"
            elif s in ["none", "no_restriction"]:
                cookie["sameSite"] = "None"
            else:
                cookie["sameSite"] = "Lax"
        if cookie.get("name") and cookie.get("value") and cookie.get("domain"):
            cookies.append(cookie)
    return cookies

def get_external_ip_and_geo(proxy):
    proxy_url = proxy['server']
    proxies = {'http': proxy_url, 'https': proxy_url}
    if proxy.get('username') and proxy.get('password'):
        host = proxy_url.replace('http://', '')
        proxy_url = f"http://{proxy['username']}:{proxy['password']}@{host}"
        proxies = {'http': proxy_url, 'https': proxy_url}

    ip = None
    geo = None
    errors = []

    ip_apis = [
        ("https://api.ipify.org?format=json", lambda r: r.json()['ip']),
        ("https://ipinfo.io/json", lambda r: r.json()['ip']),
        ("http://ip-api.com/json/", lambda r: r.json()['query']),
        ("https://api.ipgeolocation.io/ipgeo?fields=geo&apiKey=free", lambda r: r.json()['ip']),
    ]
    geo_apis = [
        ("https://ipapi.co/{ip}/json/", lambda r: r.json()),
        ("https://ipinfo.io/{ip}/json", lambda r: r.json()),
        ("http://ip-api.com/json/{ip}", lambda r: r.json()),
        ("https://api.ipgeolocation.io/ipgeo?ip={ip}&apiKey=free", lambda r: r.json()),
    ]

    for url, parser in ip_apis:
        try:
            r = requests.get(url, proxies=proxies, timeout=8)
            r.raise_for_status()
            ip = parser(r)
            break
        except Exception as e:
            errors.append(f"IP API failed: {url} | {e}")

    if not ip:
        return {'error': f"Failed to get external IP. All APIs failed. Details: {errors}"}

    for url, parser in geo_apis:
        try:
            geo_url = url.format(ip=ip)
            r = requests.get(geo_url, proxies=proxies, timeout=8)
            r.raise_for_status()
            geo = parser(r)
            break
        except Exception as e:
            errors.append(f"GEO API failed: {url} | {e}")

    if not geo:
        return {'error': f"Failed to get geo info. All APIs failed. Details: {errors}", 'ip': ip}

    result = {
        'ip': ip,
        'country': geo.get('country_name') or geo.get('country') or geo.get('countryCode'),
        'city': geo.get('city'),
        'latitude': geo.get('latitude') or geo.get('lat'),
        'longitude': geo.get('longitude') or geo.get('lon'),
        'timezone': geo.get('timezone'),
        'webrtc_ip': ip,
    }
    return result

def accept_google_popups(page, log_signal):
    try:
        consent_selectors = [
            "button:has-text('Zaakceptuj wszystko')",
            "button:has-text('Accept all')",
            "button:has-text('Accept')",
            "button:has-text('AGREE')",
            "button:has-text('Agree')",
            "button:has-text('Allow all')",
            "button:has-text('Allow')",
            "div[role='button']:has-text('Zaakceptuj wszystko')",
            "div[role='button']:has-text('Accept all')",
            "div[role='button']:has-text('Accept')",
            "div[role='button']:has-text('AGREE')",
            "div[role='button']:has-text('Agree')",
            "div[role='button']:has-text('Allow all')",
            "div[role='button']:has-text('Allow')",
        ]
        for selector in consent_selectors:
            btn = page.query_selector(selector)
            if btn and btn.is_visible():
                btn.click()
                log_emit(log_signal, f"[✓] Google consent popup accepted: {selector}")
                time.sleep(1)
                return
        buttons = page.query_selector_all("button, div[role='button']")
        for btn in buttons:
            txt = btn.inner_text().strip().lower() if hasattr(btn, "inner_text") else ""
            if any(k in txt for k in [
                "accept all", "zaakceptuj wszystko", "accept", "agree", "allow", "zgadzam", "tak"
            ]):
                try:
                    btn.click()
                    log_emit(log_signal, "[✓] Google popup accepted (fallback): " + txt)
                    time.sleep(1)
                    return
                except Exception:
                    continue
    except Exception as e:
        log_emit(log_signal, f"[!] Error accepting Google popups: {e}")

def solve_google_captcha(page, log_signal):
    try:
        # Detect Google CAPTCHA and "sorry/index" page (unusual traffic)
        if (
            page.query_selector("iframe[src*='recaptcha']")
            or page.query_selector("iframe[src*='captcha']")
            or "sorry/index" in page.url
        ):
            log_emit(log_signal, "[!] Google CAPTCHA or 'unusual traffic' detected, attempting to solve/bypass...")
            frame = None
            for f in page.frames:
                if "recaptcha" in f.url or "captcha" in f.url:
                    frame = f
                    break
            if frame:
                btn = frame.query_selector("span#recaptcha-anchor")
                if btn:
                    btn.click()
                    time.sleep(2)
                    log_emit(log_signal, "[✓] CAPTCHA checkbox clicked.")
                    time.sleep(5)
                    return True
            # If we reach here, it's not solved
            log_emit(log_signal, "[!] CAPTCHA or unusual traffic present, not solved automatically.")
            return False
        return True
    except Exception as e:
        log_emit(log_signal, f"[!] CAPTCHA solving error: {e}")
        return False

def smooth_human_scroll_until(page, stay_time_ms):
    try:
        start_time = time.time()
        height = page.evaluate("() => document.body.scrollHeight")
        current = random.randint(0, height // 5)
        direction = 1
        while (time.time() - start_time) < (stay_time_ms / 1000.0):
            if random.random() < 0.15 or current <= 0 or current >= height - 200:
                direction *= -1
            jitter = random.randint(-25, 25)
            delta = random.randint(100, 150) * direction + jitter
            current += delta
            current = max(0, min(height, current))
            page.evaluate(f"window.scrollTo(0, {current})")
            time.sleep(random.uniform(0.2, 0.3))
            if random.random() < 0.18:
                time.sleep(random.uniform(0.4, 0.7))
    except Exception:
        pass

def smooth_mouse_move(page, start_x, start_y, end_x, end_y, steps=30):
    try:
        dx = (end_x - start_x) / steps
        dy = (end_y - start_y) / steps
        for i in range(steps):
            page.mouse.move(start_x + dx * i, start_y + dy * i)
            time.sleep(random.uniform(0.03, 0.07))
    except Exception:
        pass

# ----------- BOT DETECTION EVASION SECTION -----------

def random_fingerprint():
    # Randomize fingerprint details for context
    return {
        "timezone_id": random.choice([
            "Asia/Kolkata", "America/New_York", "Europe/Berlin", "Pacific/Auckland", "Africa/Johannesburg"
        ]),
        "locale": random.choice([
            "en-US", "en-GB", "fr-FR", "de-DE", "hi-IN", "es-ES"
        ]),
        "screen": random.choice([
            {"width": 1280, "height": 720},
            {"width": 1920, "height": 1080},
            {"width": 375, "height": 667},
            {"width": 414, "height": 896}
        ]),
        "fonts": random.sample([
            "Arial", "Courier New", "Times New Roman", "Verdana", "Tahoma", "Roboto", "Fira Mono", "Consolas"
        ], k=random.randint(3, 7)),
        "plugins": random.sample([
            "Chrome PDF Viewer", "Shockwave Flash", "Widevine Content Decryption Module", "Native Client"
        ], k=random.randint(1, 4)),
        "webgl_vendor": random.choice([
            "WebKit", "Google Inc.", "Mozilla", "Intel Inc.", "NVIDIA Corporation", "AMD"
        ]),
        "webgl_renderer": random.choice([
            "ANGLE (Intel(R) HD Graphics Direct3D11 vs_5_0 ps_5_0)",
            "ANGLE (NVIDIA GeForce GTX 1050 Direct3D11 vs_5_0 ps_5_0)",
            "ANGLE (AMD Radeon Pro 5300M Direct3D11 vs_5_0 ps_5_0)"
        ]),
        "canvas_noise": random.randint(1, 1000),
        "platform": random.choice([
            "Win32", "Linux x86_64", "MacIntel", "Android", "iPhone"
        ])
    }

def apply_stealth(page, context, fingerprint):
    # Patch page context for fingerprint and anti-detection
    try:
        # Timezone
        if hasattr(context, "set_timezone_id") and fingerprint.get("timezone_id"):
            context.set_timezone_id(fingerprint["timezone_id"])
        # Locale / Language
        if hasattr(context, "add_init_script") and fingerprint.get("locale"):
            context.add_init_script(f"""
                Object.defineProperty(navigator, 'language', {{
                  get: function() {{ return '{fingerprint['locale']}'; }}
                }});
                Object.defineProperty(navigator, 'languages', {{
                  get: function() {{ return ['{fingerprint['locale']}', 'en']; }}
                }});
            """)
        # Platform
        context.add_init_script(f"""
            Object.defineProperty(navigator, 'platform', {{ get: () => '{fingerprint['platform']}' }});
        """)
        # Plugins
        plugins_js = "[" + ", ".join([f"{{name: '{p}'}}" for p in fingerprint["plugins"]]) + "]"
        context.add_init_script(f"""
            Object.defineProperty(navigator, 'plugins', {{
              get: function() {{ return {plugins_js}; }}
            }});
        """)
        # Fonts - Simulate font list by CSS injection
        fonts_css = "@font-face { font-family: " + ", ".join(fingerprint["fonts"]) + "; src: local('Arial'); }"
        page.add_style_tag(content=fonts_css)
        # Canvas fingerprint noise
        page.add_init_script(f"""
            const getContext = HTMLCanvasElement.prototype.getContext;
            HTMLCanvasElement.prototype.getContext = function(type) {{
                var ctx = getContext.apply(this, arguments);
                var origGetImageData = ctx.getImageData;
                ctx.getImageData = function(x, y, w, h) {{
                    var imgData = origGetImageData.apply(this, arguments);
                    for (var i = 0; i < imgData.data.length; i+=4) {{
                        imgData.data[i]   += {fingerprint['canvas_noise']} % 256;
                        imgData.data[i+1] += {fingerprint['canvas_noise']} % 256;
                        imgData.data[i+2] += {fingerprint['canvas_noise']} % 256;
                    }}
                    return imgData;
                }};
                return ctx;
            }};
        """)
        # WebGL vendor/renderer spoof
        page.add_init_script(f"""
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(param) {{
                if (param === 37445) {{ return "{fingerprint['webgl_vendor']}"; }}
                if (param === 37446) {{ return "{fingerprint['webgl_renderer']}"; }}
                return getParameter.apply(this, arguments);
            }};
        """)
    except Exception as e:
        log_emit(None, f"[Stealth] Error patching fingerprint: {e}")

# ----------- END BOT DETECTION EVASION SECTION -----------

def google_keyword_search(context, proxy, keywords, main_url, stay_time_ms, user_agent, log_signal):
    page = context.new_page()
    fingerprint = random_fingerprint()
    apply_stealth(page, context, fingerprint)
    try:
        log_emit(log_signal, f"[+] Visiting google.com for keyword search with proxy {proxy['server'] if proxy else 'No Proxy'}")
        page.goto("https://www.google.com", timeout=40000)
        page.wait_for_load_state("domcontentloaded")
        time.sleep(1.2)
        accept_google_popups(page, log_signal)
        if not solve_google_captcha(page, log_signal):
            log_emit(log_signal, "[!] CAPTCHA or 'unusual traffic' detected. Skipping keyword search and opening main domain directly...")
            page.close()
            direct_page = context.new_page()
            fingerprint = random_fingerprint()
            apply_stealth(direct_page, context, fingerprint)
            try:
                direct_page.goto(main_url, timeout=40000)
                direct_page.wait_for_load_state("domcontentloaded")
                time.sleep(1)
                log_emit(log_signal, f"[✓] Visited main domain {main_url} after CAPTCHA/sorry.")
                smooth_human_scroll_until(direct_page, stay_time_ms)
                log_emit(log_signal, f"[✓] Keyword session finished for {main_url} after CAPTCHA/sorry.")
            except Exception as e:
                log_emit(log_signal, f"[!] Failed to open main domain after CAPTCHA/sorry: {e}")
            finally:
                direct_page.close()
            return "captcha_direct"
        for kw in keywords:
            if stop_event.is_set():
                break
            try:
                log_emit(log_signal, f"[→] Searching keyword: {kw}")
                search_bar = None
                for selector in ["input[name='q']", "textarea[name='q']", "input[type='text']"]:
                    search_bar = page.query_selector(selector)
                    if search_bar:
                        break
                if not search_bar:
                    page.mouse.click(350, 80)
                    time.sleep(0.5)
                    search_bar = page.query_selector("input[name='q']")
                if search_bar:
                    bbox = search_bar.bounding_box()
                    smooth_mouse_move(page, random.randint(int(bbox['x']), int(bbox['x'] + bbox['width'])),
                                      random.randint(int(bbox['y']), int(bbox['y'] + bbox['height'])),
                                      int(bbox['x'] + bbox['width'] // 2), int(bbox['y'] + bbox['height'] // 2))
                    search_bar.click()
                    time.sleep(random.uniform(0.3, 0.8))
                    search_bar.fill("")
                    for char in kw:
                        search_bar.type(char)
                        time.sleep(random.uniform(0.07, 0.19))
                    time.sleep(random.uniform(0.4, 0.8))
                    search_bar.press("Enter")
                    page.wait_for_load_state("domcontentloaded")
                    time.sleep(random.uniform(2.0, 2.8))
                else:
                    log_emit(log_signal, "[!] Google search bar not found, skipping keyword.")
                    continue
                accept_google_popups(page, log_signal)
                if "sorry/index" in page.url:
                    log_emit(log_signal, "[!] Google 'unusual traffic' detected after search. Opening main domain directly...")
                    page.close()
                    direct_page = context.new_page()
                    fingerprint = random_fingerprint()
                    apply_stealth(direct_page, context, fingerprint)
                    try:
                        direct_page.goto(main_url, timeout=40000)
                        direct_page.wait_for_load_state("domcontentloaded")
                        time.sleep(1)
                        log_emit(log_signal, f"[✓] Visited main domain {main_url} after CAPTCHA/sorry.")
                        smooth_human_scroll_until(direct_page, stay_time_ms)
                        log_emit(log_signal, f"[✓] Keyword session finished for {main_url} after CAPTCHA/sorry.")
                    except Exception as e:
                        log_emit(log_signal, f"[!] Failed to open main domain after CAPTCHA/sorry: {e}")
                    finally:
                        direct_page.close()
                    return "captcha_direct"
                found = False
                results = page.query_selector_all("div.g, div[data-hveid]")
                for result in results:
                    link = result.query_selector("a")
                    if link:
                        href = link.get_attribute("href")
                        main_url_simplified = main_url.lower().replace("http://", "").replace("https://", "").replace("www.", "")
                        if href and main_url_simplified in href.lower():
                            log_emit(log_signal, f"[✓] Found domain {main_url} in results, clicking...")
                            smooth_mouse_move(page, *random.sample(range(100, 600), 2), *random.sample(range(400, 800), 2))
                            link.click()
                            page.wait_for_load_state("domcontentloaded")
                            time.sleep(2)
                            found = True
                            break
                if not found:
                    log_emit(log_signal, f"[!] Domain {main_url} not found in first page of results for keyword '{kw}'. Skipping to next keyword.")
                    continue
                log_emit(log_signal, f"[~] Scrolling {main_url} for {stay_time_ms} ms")
                smooth_human_scroll_until(page, stay_time_ms)
                log_emit(log_signal, f"[✓] Keyword session finished for {main_url}")
                break
            except Exception as e:
                log_emit(log_signal, f"[!] Error in keyword session: {e}\n{traceback.format_exc()}")
    except Exception as e:
        log_emit(log_signal, f"[!] Failed to load Google: {e}")
    finally:
        page.close()

def simulate_session(proxy, url_time_list, user_agents, device_type, log_signal, cookies=None, referrer=None, export_queue=None,
                    enable_keyword_search=False, main_url=None, keywords=None, stay_time_ms=None):
    browser = None
    context = None
    try:
        proxy_info = get_external_ip_and_geo(proxy)
        if 'error' in proxy_info:
            log_emit(log_signal, f"[Proxy GEO] {proxy_info['error']}")
        else:
            log_emit(log_signal,
                f"[Proxy GEO] IP: {proxy_info['ip']} | Country: {proxy_info['country']} | City: {proxy_info['city']} "
                f"| Lat: {proxy_info['latitude']} | Lon: {proxy_info['longitude']} | Timezone: {proxy_info['timezone']} | WebRTC: {proxy_info['webrtc_ip']}"
            )
        if stop_event.is_set():
            return
        with sync_playwright() as p:
            browser_type = p.chromium
            user_agent = random.choice(user_agents) if user_agents else (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
                if device_type == 'desktop' else
                "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36"
            )
            browser_args = {"headless": False}
            if proxy:
                proxy_config = {"server": proxy["server"]}
                if proxy.get("username"):
                    proxy_config["username"] = proxy["username"]
                if proxy.get("password"):
                    proxy_config["password"] = proxy["password"]
                browser_args["proxy"] = proxy_config
            browser_opened = False
            try:
                browser = browser_type.launch(**browser_args)
                browser_opened = True
            except Exception as e:
                log_emit(log_signal, f"[!] Browser open failed: {e}")
            if not browser_opened:
                return
            try:
                fingerprint = random_fingerprint()
                context = browser.new_context(
                    user_agent=user_agent,
                    viewport=fingerprint["screen"],
                    is_mobile=(device_type != 'desktop'),
                    device_scale_factor=random.choice([1,2,3]),
                    has_touch=(device_type != 'desktop'),
                    locale=fingerprint["locale"]
                )
                if 'latitude' in proxy_info and 'longitude' in proxy_info:
                    try:
                        context.set_geolocation({"latitude": float(proxy_info['latitude']), "longitude": float(proxy_info['longitude'])})
                    except Exception:
                        pass
                if 'timezone' in proxy_info and proxy_info['timezone']:
                    try:
                        context.set_timezone_id(proxy_info['timezone'])
                    except Exception:
                        pass
            except Exception as e:
                log_emit(log_signal, f"[!] Context could not be created: {e}")
                return
            if cookies:
                try:
                    cookies_normalized = normalize_cookies(cookies)
                    if cookies_normalized:
                        context.add_cookies(cookies_normalized)
                        log_emit(log_signal, f"[+] Cookies injected.")
                    else:
                        log_emit(log_signal, f"[!] Cookies could not be normalized. Skipped injection.")
                except Exception as e:
                    log_emit(log_signal, f"[!] Cookie inject error: {e}")
            try:
                if enable_keyword_search and main_url and keywords and stay_time_ms:
                    result = google_keyword_search(context, proxy, keywords, main_url, stay_time_ms, user_agent, log_signal)
                    log_emit(log_signal, f"[✓] Finished keyword search session.")
                else:
                    for url, url_stay_time_ms in url_time_list:
                        if stop_event.is_set():
                            break
                        page = context.new_page()
                        fingerprint = random_fingerprint()
                        apply_stealth(page, context, fingerprint)
                        log_emit(log_signal, f"[+] Visiting {url} using {proxy['server'] if proxy else 'No Proxy'} as {device_type}")
                        try:
                            page.goto(url, timeout=120000, wait_until="domcontentloaded")
                            page.wait_for_load_state('load')
                            time.sleep(1)
                        except Exception as e:
                            log_emit(log_signal, f"[!] Proxy failed or page not loaded for: {proxy['server'] if proxy else 'No Proxy'} | Reason: {e}")
                            page.close()
                            continue
                        try:
                            agree_selectors = [
                                "button:has-text('Agree')", "button:has-text('AGREE')", "button:has-text('I Agree')",
                                "button:has-text('Accept')", "button:has-text('ALLOW ALL')", "button:has-text('Allow all')",
                                "button:has-text('CONFIRM')", "button:has-text('Confirm')",
                                "text=Agree", "text=I Agree", "text=Accept", "text=ALLOW ALL", "text=Allow all", "text=CONFIRM", "text=Confirm"
                            ]
                            found = False
                            for selector in agree_selectors:
                                if stop_event.is_set(): return
                                try:
                                    btn = page.query_selector(selector)
                                    if btn and btn.is_visible():
                                        btn.click()
                                        log_emit(log_signal, "[✓] Cookie/Privacy/Confirm popup auto-accepted.")
                                        found = True
                                        break
                                except Exception as e:
                                    continue
                        except Exception as e:
                            log_emit(log_signal, f"[!] Error auto-accepting popup: {e}\n{traceback.format_exc()}")
                        x1, y1 = random.randint(100, 400), random.randint(100, 300)
                        x2, y2 = random.randint(500, 800), random.randint(300, 600)
                        smooth_mouse_move(page, x1, y1, x2, y2)
                        smooth_human_scroll_until(page, url_stay_time_ms)
                        log_emit(log_signal, f"[~] Stayed for {url_stay_time_ms} ms (human-like up/down scroll)")
                        page.close()
                    log_emit(log_signal, f"[✓] Finished normal session {proxy['server'] if proxy else 'No Proxy'}")
            except Exception as e:
                log_emit(log_signal, f"[!] Error: {e}\n{traceback.format_exc()}")
            finally:
                try: context.close()
                except: pass
                try: browser.close()
                except: pass
    except Exception as e:
        log_emit(log_signal, f"[!] Error: {e}\n{traceback.format_exc()}")

class SimulatorGUI(QWidget):
    log_signal = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} – Human Based Traffic Simulator {APP_VERSION}")
        self.setWindowIcon(QIcon("favicon.ico"))
        self.setGeometry(100, 100, 900, 800)
        self.setStyleSheet("""
            QWidget { background-color: #1b1e1f; color: #e8e8e8; font-family: monospace; }
            QLabel { font-size: 13px; }
            QComboBox { background-color: #2a2e2e; color: #e8e8e8; border: 2px solid #13df13; padding: 5px; font-size: 13px; font-family: monospace; selection-background-color: #304050; }
            QComboBox QAbstractItemView { background: #2a2e2e; color: #e8e8e8; selection-background-color: #304050; }
            QTextEdit { background-color: #111; color: #32ff32; font-family: 'Fira Mono', 'Consolas', 'monospace'; font-size: 14px; font-weight: bold; border: 1.5px solid #13df13; }
            QLineEdit { background-color: #2a2e2e; color: #e8e8e8; border: 2px solid #13df13; padding: 4px; font-family: 'Fira Mono', 'Consolas', monospace; font-size: 14px; font-weight: bold; }
            QPushButton { background-color: #4caf50; color: white; padding: 8px 15px; font-weight: bold; border: none; }
            QPushButton:hover { background-color: #43a047; }
            QPushButton:disabled { background-color: #2d5f2f; }
            QTableWidget { background-color: #232526; color: #e8e8e8; border: 2px solid #13df13; font-size: 13px; }
            QHeaderView::section { background-color: #232526; color: #13df13; border: 2px solid #13df13; font-weight: bold; font-size: 13px; }
        """)
        main_layout = QVBoxLayout(self)
        center_layout = QHBoxLayout()
        center_layout.setSpacing(20)
        self.url_table = QTableWidget(0, 3)
        self.url_table.setHorizontalHeaderLabels(["Target Website", "Stay Time (ms)", ""])
        self.url_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.url_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.url_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.url_table.setMinimumHeight(130)
        self.url_table.setMaximumHeight(200)
        self.url_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.url_table.setEditTriggers(QAbstractItemView.AllEditTriggers)
        self.url_table.verticalHeader().setVisible(False)
        self.url_table.setShowGrid(True)
        self.url_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.add_url_btn = QPushButton("Add URL")
        self.add_url_btn.clicked.connect(self.add_url_row)
        url_btn_layout = QHBoxLayout()
        url_btn_layout.addWidget(QLabel("Target Websites:"))
        url_btn_layout.addWidget(self.add_url_btn)
        url_btn_layout.addStretch(1)
        url_box_layout = QVBoxLayout()
        url_box_layout.addLayout(url_btn_layout)
        url_box_layout.addWidget(self.url_table)
        device_percent_layout = QHBoxLayout()
        device_percent_layout.addWidget(QLabel("Android %:"))
        self.android_percent_input = QLineEdit()
        self.android_percent_input.setPlaceholderText("e.g. 60")
        device_percent_layout.addWidget(self.android_percent_input)
        device_percent_layout.addSpacing(10)
        device_percent_layout.addWidget(QLabel("Desktop %:"))
        self.desktop_percent_input = QLineEdit()
        self.desktop_percent_input.setPlaceholderText("e.g. 40")
        device_percent_layout.addWidget(self.desktop_percent_input)
        device_percent_layout.addSpacing(10)
        device_percent_layout.addWidget(QLabel("Max Sessions/Threads:"))
        self.thread_input = QLineEdit()
        self.thread_input.setPlaceholderText("e.g. 5")
        device_percent_layout.addWidget(self.thread_input)
        device_percent_layout.addStretch(1)
        self.referrer_dropdown = QComboBox()
        self.referrer_dropdown.addItems([
            "Google", "Facebook", "YouTube", "Yahoo", "Bing", "Direct"
        ])
        self.referrer_dropdown.setStyleSheet("background-color: #2a2e2e; color: #e8e8e8; border: 2px solid #13df13; padding: 4px; font-family: 'Fira Mono', 'Consolas', monospace; font-size: 14px; font-weight: bold;")
        self.enable_keyword_checkbox = QCheckBox("Enable Keyword Search (Google)")
        self.enable_keyword_checkbox.setStyleSheet("color: #32ff32; font-weight: bold; font-size: 14px; margin-top: 8px;")
        self.keyword_main_url_input = QLineEdit()
        self.keyword_main_url_input.setPlaceholderText("Enter main domain full link (e.g. https://www.example.com)")
        self.keyword_keywords_input = QLineEdit()
        self.keyword_keywords_input.setPlaceholderText("Comma separated keywords (e.g. shoes, buy shoes, best shoes 2025)")
        self.keyword_stay_time_input = QLineEdit()
        self.keyword_stay_time_input.setPlaceholderText("Stay time (ms) e.g. 8000")
        for inp in [self.keyword_main_url_input, self.keyword_keywords_input, self.keyword_stay_time_input]:
            inp.setStyleSheet("background-color: #2a2e2e; color: #e8e8e8; border: 2px solid #13df13; padding: 4px; font-family: 'Fira Mono', 'Consolas', monospace; font-size: 14px; font-weight: bold;")
        self.keyword_main_url_input.setEnabled(False)
        self.keyword_keywords_input.setEnabled(False)
        self.keyword_stay_time_input.setEnabled(False)
        self.url_table.setEnabled(True)
        self.add_url_btn.setEnabled(True)
        self.referrer_dropdown.setEnabled(True)
        self.enable_keyword_checkbox.stateChanged.connect(self.toggle_keyword_fields)
        left_layout = QFormLayout()
        left_layout.setLabelAlignment(Qt.AlignRight)
        left_layout.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        left_layout.setSpacing(15)
        left_layout.addRow(url_box_layout)
        left_layout.addRow(device_percent_layout)
        left_layout.addRow(QLabel("Referral Source:"), self.referrer_dropdown)
        left_layout.addRow(self.enable_keyword_checkbox)
        left_layout.addRow(QLabel("Main URL (full link):"), self.keyword_main_url_input)
        left_layout.addRow(QLabel("Keywords:"), self.keyword_keywords_input)
        left_layout.addRow(QLabel("Stay Time (ms):"), self.keyword_stay_time_input)
        right_layout = QVBoxLayout()
        right_layout.setAlignment(Qt.AlignTop)
        self.browse_button = QPushButton("Browse Proxies")
        self.browse_button.clicked.connect(self.load_proxy_file)
        self.proxy_status = QLabel("❌ Not imported")
        right_layout.addWidget(self.browse_button)
        right_layout.addWidget(self.proxy_status)
        self.ua_button = QPushButton("Browse User-Agents")
        self.ua_button.clicked.connect(self.load_user_agents)
        self.ua_status = QLabel("❌ Not imported")
        right_layout.addWidget(self.ua_button)
        right_layout.addWidget(self.ua_status)
        self.cookies_button = QPushButton("Browse Cookies")
        self.cookies_button.clicked.connect(self.load_cookies)
        self.cookies_status = QLabel("❌ Not imported")
        right_layout.addWidget(self.cookies_button)
        right_layout.addWidget(self.cookies_status)
        right_layout.addStretch(1)
        center_layout.addLayout(left_layout, 3)
        center_layout.addLayout(right_layout, 1)
        center_layout.setStretch(0, 3)
        center_layout.setStretch(1, 1)
        main_layout.addLayout(center_layout)
        action_layout = QHBoxLayout()
        self.start_button = QPushButton("START")
        self.start_button.clicked.connect(self.start_simulation)
        self.stop_button = QPushButton("STOP")
        self.stop_button.clicked.connect(self.stop_simulation)
        self.stop_button.setEnabled(False)
        self.update_button = QPushButton("Check for Update")
        self.update_button.clicked.connect(self.manual_check_update)
        action_layout.addWidget(self.start_button)
        action_layout.addWidget(self.stop_button)
        action_layout.addWidget(self.update_button)
        self.session_counter = QLabel("Active Sessions: 0 | Left Sessions: 0")
        self.session_counter.setStyleSheet("font-size: 13px; font-weight: bold;")
        action_layout.addStretch(1)
        action_layout.addWidget(self.session_counter)
        main_layout.addLayout(action_layout)
        self.update_badge = QPushButton("New Update Available!")
        self.update_badge.setStyleSheet("""
            background-color: #d32f2f;
            color: #fff;
            font-weight: bold;
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 13px;
        """)
        self.update_badge.setVisible(False)
        self.update_badge.clicked.connect(self.perform_update)
        main_layout.addWidget(self.update_badge)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFixedHeight(140)
        self.log_output.setStyleSheet("""
            background-color: #111;
            color: #32ff32;
            font-family: 'Fira Mono', 'Consolas', 'monospace';
            font-size: 14px;
            font-weight: bold;
            border: 1.5px solid #13df13;
        """)
        main_layout.addWidget(QLabel("Log:"))
        main_layout.addWidget(self.log_output)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.hide()
        main_layout.addWidget(self.progress_bar)
        footer = QLabel(
            f"<b>{APP_NAME} {APP_VERSION}</b> – Simulating Real Traffic. The Smart Way.<br>"
            "📢 <b>Disclaimer:</b> Use this tool responsibly for educational or testing purposes only.<br>"
            "🚫 Unauthorized misuse of traffic simulation can lead to legal consequences.<br>"
            "<b>🌐</b> <a href='https://adsenseloadingmethod.com' style='color:#80cbc4;'>adsenseloadingmethod.com</a> | "
            "<b>📞</b> +44 7776517786 | "
            "<b>👨‍💻</b> <a href='https://asadwebdev.com' style='color:#cf1130; text-decoration:none;'>CODEWITHASAD</a>"
        )
        footer.setOpenExternalLinks(True)
        footer.setWordWrap(True)
        footer.setAlignment(Qt.AlignCenter)
        footer.setStyleSheet("font-size: 12px; margin-top: 8px; color: #aaa; background: #161819; border-top: 1px solid #333; padding: 7px;")
        main_layout.addWidget(footer)
        self.proxy_lines = []
        self.user_agents = []
        self.cookies_lines = None
        self.threads = []
        self.counter_timer = QTimer()
        self.counter_timer.timeout.connect(self.update_session_counters)
        self.counter_timer.start(1000)
        self.last_exported_cookies = None
        self.log_signal.connect(self.add_log)
        self.check_for_update_background()
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.check_for_update_background)
        self.update_timer.start(60*60*1000)
        self.add_url_row()

    def toggle_keyword_fields(self, state):
        enabled = (state == Qt.Checked)
        self.keyword_main_url_input.setEnabled(enabled)
        self.keyword_keywords_input.setEnabled(enabled)
        self.keyword_stay_time_input.setEnabled(enabled)
        self.url_table.setEnabled(not enabled)
        self.add_url_btn.setEnabled(not enabled)
        self.referrer_dropdown.setEnabled(not enabled)

    def add_url_row(self):
        row = self.url_table.rowCount()
        self.url_table.insertRow(row)
        url_edit = QLineEdit()
        stay_time_edit = QLineEdit()
        stay_time_edit.setPlaceholderText("ms (e.g. 5000)")
        url_edit.setPlaceholderText("https://example.com")
        url_edit.setFont(QFont("Fira Mono, Consolas", 13))
        stay_time_edit.setFont(QFont("Fira Mono, Consolas", 13))
        url_edit.setStyleSheet("background-color: #2a2e2e; color: #e8e8e8; border: 2px solid #13df13; padding: 4px; font-family: 'Fira Mono', 'Consolas', monospace; font-size: 14px; font-weight: bold;")
        stay_time_edit.setStyleSheet("background-color: #2a2e2e; color: #e8e8e8; border: 2px solid #13df13; padding: 4px; font-family: 'Fira Mono', 'Consolas', monospace; font-size: 14px; font-weight: bold;")
        remove_btn = QPushButton("Remove")
        remove_btn.setStyleSheet("background-color: #cf1130; color: white; font-weight: bold; border-radius: 3px;")
        remove_btn.clicked.connect(lambda: self.remove_url_row(row))
        self.url_table.setCellWidget(row, 0, url_edit)
        self.url_table.setCellWidget(row, 1, stay_time_edit)
        self.url_table.setCellWidget(row, 2, remove_btn)

    def remove_url_row(self, row):
        self.url_table.removeRow(row)

    def get_url_time_list(self):
        url_time_list = []
        for row in range(self.url_table.rowCount()):
            url_edit = self.url_table.cellWidget(row, 0)
            time_edit = self.url_table.cellWidget(row, 1)
            if url_edit is None or time_edit is None:
                continue
            url = url_edit.text().strip()
            time_str = time_edit.text().strip()
            if not url or not time_str:
                continue
            if not url.startswith("http"):
                return None, f"Invalid URL format in row {row+1}!"
            try:
                stay_time = int(time_str)
                if stay_time <= 0:
                    return None, f"Stay time must be positive in row {row+1}!"
            except Exception:
                return None, f"Stay time must be a positive integer in row {row+1}!"
            url_time_list.append((url, stay_time))
        if not url_time_list:
            return None, "At least one valid URL and stay time is required!"
        return url_time_list, None

    def add_log(self, msg):
        self.log_output.append(msg)
        self.log_output.ensureCursorVisible()
        QApplication.processEvents()

    def check_for_update_background(self):
        try:
            r = requests.get(UPDATE_VERSION_URL, timeout=5)
            if r.status_code == 200:
                server_version = r.text.strip()
                if server_version > APP_VERSION:
                    self.update_badge.setVisible(True)
                    self.log_output.append(f"[Update] New version {server_version} available!")
                else:
                    self.update_badge.setVisible(False)
        except Exception:
            pass

    def manual_check_update(self):
        self.check_for_update_background()
        if self.update_badge.isVisible():
            QMessageBox.information(self, "Update", "A new update is available! Click the red badge to update.")
        else:
            QMessageBox.information(self, "Update", "You have the latest version.")

    def perform_update(self):
        local_exe = os.path.abspath(sys.argv[0])
        temp_dir = tempfile.gettempdir()
        new_exe = os.path.join(temp_dir, "HumanexV6_new.exe")
        bat_path = os.path.join(temp_dir, "update_and_run.bat")
        self.update_badge.setEnabled(False)
        self.log_output.append("[Update] Downloading update...")
        try:
            r = requests.get(UPDATE_EXE_URL, stream=True, timeout=30)
            r.raise_for_status()
            with open(new_exe, "wb") as f:
                for chunk in r.iter_content(1024*1024):
                    f.write(chunk)
            with open(bat_path, "w") as bat:
                bat.write(f"""@echo off
timeout /t 2 >nul
del "{local_exe}"
move "{new_exe}" "{local_exe}"
start "" "{local_exe}"
del "%~f0"
""")
            self.log_output.append("[Update] Update downloaded. App will now restart...")
            QMessageBox.information(self, "Update", "App will now close and update itself.")
            subprocess.Popen(['cmd', '/c', 'start', '', bat_path], shell=True)
            QApplication.quit()
        except Exception as e:
            self.log_output.append(f"[Update] Update failed: {e}")
            QMessageBox.warning(self, "Update Error", f"Update failed: {e}")
        finally:
            self.update_badge.setEnabled(True)

    def load_proxy_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Proxy File", "", "Text Files (*.txt)")
        if path:
            try:
                with open(path, 'r') as f:
                    self.proxy_lines = [line.strip() for line in f if line.strip()]
                self.proxy_status.setText("✅ Imported")
                log_emit(self.log_signal, f"[+] Loaded {len(self.proxy_lines)} proxies.")
            except Exception as e:
                self.proxy_status.setText("❌ Not imported")
                log_emit(self.log_signal, f"[!] Error loading proxies: {e}")

    def load_user_agents(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select User-Agents File", "", "Text Files (*.txt)")
        if path:
            try:
                with open(path, 'r') as f:
                    self.user_agents = [line.strip() for line in f if line.strip()]
                self.ua_status.setText("✅ Imported")
                log_emit(self.log_signal, f"[+] Loaded {len(self.user_agents)} user-agents.")
            except Exception as e:
                self.ua_status.setText("❌ Not imported")
                log_emit(self.log_signal, f"[!] Error loading user-agents: {e}")

    def load_cookies(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Cookies File", "", "JSON/Text Files (*.json *.txt)")
        if path:
            try:
                self.progress_bar.setValue(0)
                self.progress_bar.show()
                QApplication.processEvents()
                with open(path, 'r', encoding='utf-8') as f:
                    data = f.read()
                cookies_normalized = None
                try:
                    json_data = json.loads(data)
                    cookies_normalized = normalize_cookies(json_data)
                except Exception:
                    cookies_normalized = normalize_cookies(parse_netscape_cookies(data))
                if cookies_normalized:
                    self.cookies_lines = cookies_normalized
                    self.cookies_status.setText("✅ Imported")
                    log_emit(self.log_signal, f"[+] Loaded {len(self.cookies_lines)} cookies from file.")
                    self.progress_bar.setValue(100)
                    QApplication.processEvents()
                else:
                    self.cookies_lines = None
                    self.cookies_status.setText("❌ Not imported")
                    log_emit(self.log_signal, f"[!] Error: File is not a valid/compatible cookies format.")
                    self.progress_bar.setValue(0)
            except Exception as e:
                self.cookies_lines = None
                self.cookies_status.setText("❌ Not imported")
                log_emit(self.log_signal, f"[!] Error loading cookies: {e}")
                self.progress_bar.setValue(0)
            finally:
                QTimer.singleShot(1200, self.progress_bar.hide)

    def update_session_counters(self):
        alive_threads = sum(1 for t in self.threads if t.is_alive())
        left_sessions = self.proxy_queue.qsize() if hasattr(self, "proxy_queue") else 0
        self.session_counter.setText(
            f"Active Sessions: {alive_threads} | Left Sessions: {left_sessions}"
        )

    def disable_inputs(self):
        for w in [self.url_table, self.add_url_btn, self.browse_button, self.ua_button, self.cookies_button, self.android_percent_input, self.desktop_percent_input, self.thread_input, self.start_button, self.referrer_dropdown, self.enable_keyword_checkbox, self.keyword_main_url_input, self.keyword_keywords_input, self.keyword_stay_time_input]:
            w.setEnabled(False)
        self.start_button.setText("RUNNING...")
        self.stop_button.setEnabled(True)
        QApplication.processEvents()

    def enable_inputs(self):
        for w in [self.url_table, self.add_url_btn, self.browse_button, self.ua_button, self.cookies_button, self.android_percent_input, self.desktop_percent_input, self.thread_input, self.start_button, self.referrer_dropdown, self.enable_keyword_checkbox, self.keyword_main_url_input, self.keyword_keywords_input, self.keyword_stay_time_input]:
            w.setEnabled(True)
        self.start_button.setText("START")
        self.stop_button.setEnabled(False)
        QApplication.processEvents()

    def stop_simulation(self):
        stop_event.set()
        log_emit(self.log_signal, "[!] Stopping all sessions...")
        if hasattr(self, "proxy_queue"):
            while not self.proxy_queue.empty():
                try:
                    self.proxy_queue.get_nowait()
                    self.proxy_queue.task_done()
                except Exception:
                    break
        for t in self.threads:
            t.join(timeout=2)
        self.enable_inputs()
        log_emit(self.log_signal, "[✓] All sessions stopped. Ready for new work.")

    def check_threads_completion(self):
        alive_threads = sum(1 for t in self.threads if t.is_alive())
        left_sessions = self.proxy_queue.qsize() if hasattr(self, "proxy_queue") else 0
        if alive_threads == 0 and left_sessions == 0:
            self.enable_inputs()
            log_emit(self.log_signal, "\n[✓] All sessions completed!")
        else:
            QTimer.singleShot(500, self.check_threads_completion)

    def start_simulation(self):
        global stop_event
        stop_event.clear()
        self.disable_inputs()
        enable_keyword_search = self.enable_keyword_checkbox.isChecked()
        main_url = self.keyword_main_url_input.text().strip() if enable_keyword_search else None
        keywords = [k.strip() for k in self.keyword_keywords_input.text().split(",") if k.strip()] if enable_keyword_search else None
        stay_time_ms = int(self.keyword_stay_time_input.text().strip()) if enable_keyword_search and self.keyword_stay_time_input.text().strip().isdigit() else None
        url_time_list, err = self.get_url_time_list()
        if not enable_keyword_search and err:
            log_emit(self.log_signal, f"[!] {err}")
            self.enable_inputs()
            return
        if enable_keyword_search and (not main_url or not keywords or not stay_time_ms):
            log_emit(self.log_signal, "[!] Provide Main URL (full link), at least one keyword, and stay time for keyword search.")
            self.enable_inputs()
            return
        max_threads_str = self.thread_input.text().strip()
        android_percent_str = self.android_percent_input.text().strip()
        desktop_percent_str = self.desktop_percent_input.text().strip()
        ref_source = self.referrer_dropdown.currentText()
        ref_map = {
            "Google": "https://www.google.com/",
            "Facebook": "https://www.facebook.com/",
            "YouTube": "https://www.youtube.com/",
            "Yahoo": "https://www.yahoo.com/",
            "Bing": "https://www.bing.com/",
            "Direct": None
        }
        self.referrer = ref_map.get(ref_source)
        if not max_threads_str.isdigit():
            log_emit(self.log_signal, "[!] Enter valid number for threads.")
            self.enable_inputs()
            return
        if not android_percent_str.isdigit() or not desktop_percent_str.isdigit():
            log_emit(self.log_signal, "[!] Enter valid percentages for Android and Desktop.")
            self.enable_inputs()
            return
        android_percent = int(android_percent_str)
        desktop_percent = int(desktop_percent_str)
        if android_percent + desktop_percent != 100:
            log_emit(self.log_signal, "[!] Android % + Desktop % must equal 100.")
            self.enable_inputs()
            return
        max_threads = int(max_threads_str)
        if not self.proxy_lines:
            log_emit(self.log_signal, "[!] Load proxy list first.")
            self.enable_inputs()
            return
        total_sessions = len(self.proxy_lines)
        android_sessions = int((android_percent / 100) * total_sessions)
        desktop_sessions = total_sessions - android_sessions
        device_types = ['mobile'] * android_sessions + ['desktop'] * desktop_sessions
        random.shuffle(device_types)
        self.proxy_queue = queue.Queue()
        for i, line in enumerate(self.proxy_lines):
            proxy = parse_proxy(line)
            if proxy:
                self.proxy_queue.put((proxy, device_types[i]))
            else:
                log_emit(self.log_signal, f"[!] Invalid proxy format: {line}")
        self.max_threads = max_threads
        self.threads = []
        def thread_worker():
            while not stop_event.is_set():
                try:
                    proxy, device_type = self.proxy_queue.get(timeout=1)
                except queue.Empty:
                    break
                try:
                    simulate_session(
                        proxy,
                        url_time_list,
                        self.user_agents,
                        device_type,
                        self.log_signal,
                        self.cookies_lines if self.cookies_lines else None,
                        self.referrer,
                        None,
                        enable_keyword_search=enable_keyword_search,
                        main_url=main_url,
                        keywords=keywords,
                        stay_time_ms=stay_time_ms,
                    )
                except Exception as e:
                    log_emit(self.log_signal, f"[!] Thread error: {e}")
                finally:
                    self.proxy_queue.task_done()
        for i in range(self.max_threads):
            t = threading.Thread(target=thread_worker, name=f"WorkerThread-{i+1}", daemon=True)
            t.start()
            self.threads.append(t)
        QTimer.singleShot(1000, self.check_threads_completion)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    license_win = LicenseWindow()
    license_win.show()
    app.exec_()
    if getattr(license_win, "verified", False):
        gui = SimulatorGUI()
        gui.show()
        sys.exit(app.exec_())
    else:
        QMessageBox.critical(None, "License Error", "License verification failed.\nApplication will now exit.")
        sys.exit(1)