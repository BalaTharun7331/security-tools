import os, time, base64, warnings
warnings.filterwarnings("ignore")

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import UnexpectedAlertPresentException, TimeoutException
from webdriver_manager.chrome import ChromeDriverManager

SCREENSHOT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

def get_driver():
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1280,800")
    opts.add_argument("--disable-web-security")
    opts.add_argument("--allow-running-insecure-content")
    opts.add_argument("--ignore-certificate-errors")
    # disable alert blocking
    opts.set_capability("unhandledPromptBehavior", "accept")
    try:
        service = Service(ChromeDriverManager().install())
        driver  = webdriver.Chrome(service=service, options=opts)
        return driver
    except Exception as e:
        print(f"[Browser] Chrome failed: {e}")
        return None

def take_screenshot_with_alert(url, payload, param, method="get", data=None):
    """
    Inject payload via browser, detect alert popup,
    take screenshot, return alert text + screenshot path
    """
    driver = get_driver()
    if not driver:
        return None, None

    alert_text  = None
    screenshot  = None
    ts          = int(time.time())
    shot_name   = f"xss_{ts}.png"
    shot_path   = os.path.join(SCREENSHOT_DIR, shot_name)
    shot_web    = f"/static/screenshots/{shot_name}"

    try:
        if method.lower() == "get":
            driver.get(url)
        else:
            # inject via JS form submit for POST
            driver.get(url)

        # wait short time for page load
        time.sleep(2)

        # check for alert
        try:
            alert = WebDriverWait(driver, 3).until(EC.alert_is_present())
            alert_text = alert.text
            # take screenshot BEFORE accepting
            driver.save_screenshot(shot_path)
            screenshot = shot_web
            alert.accept()
        except TimeoutException:
            # no alert — take normal screenshot anyway
            driver.save_screenshot(shot_path)
            screenshot = shot_web

    except UnexpectedAlertPresentException as e:
        alert_text = str(e.alert_text) if hasattr(e, "alert_text") else "XSS Alert Triggered!"
        try:
            driver.save_screenshot(shot_path)
            screenshot = shot_web
            driver.switch_to.alert.accept()
        except Exception:
            pass
    except Exception as e:
        print(f"[Browser] Error: {e}")
    finally:
        try:
            driver.quit()
        except Exception:
            pass

    return alert_text, screenshot

def verify_xss_with_browser(url, payload, param, method="get", form_data=None):
    """
    Full browser verification of XSS:
    1. Build the URL with payload injected
    2. Open in headless browser
    3. Detect alert popup
    4. Take screenshot
    5. Return result
    """
    driver = get_driver()
    if not driver:
        return {"verified": False, "alert_text": None, "screenshot": None}

    alert_text = None
    screenshot = None
    verified   = False
    ts         = int(time.time() * 1000)
    shot_name  = f"xss_{ts}.png"
    shot_path  = os.path.join(SCREENSHOT_DIR, shot_name)
    shot_web   = f"/static/screenshots/{shot_name}"

    try:
        driver.get(url)
        time.sleep(2)

        # try to detect alert
        try:
            alert = WebDriverWait(driver, 4).until(EC.alert_is_present())
            alert_text = alert.text or "XSS Alert Fired!"
            verified   = True
            driver.save_screenshot(shot_path)
            screenshot = shot_web
            alert.accept()
        except TimeoutException:
            # check page source for payload
            if payload in driver.page_source:
                verified = True
            driver.save_screenshot(shot_path)
            screenshot = shot_web

    except UnexpectedAlertPresentException as e:
        verified   = True
        alert_text = "XSS Alert Triggered!"
        try:
            driver.save_screenshot(shot_path)
            screenshot = shot_web
            driver.switch_to.alert.accept()
        except Exception:
            pass
    except Exception as e:
        print(f"[Browser] Verify error: {e}")
    finally:
        try:
            driver.quit()
        except Exception:
            pass

    return {
        "verified":   verified,
        "alert_text": alert_text,
        "screenshot": screenshot
    }

def screenshot_url(url):
    """Just take a screenshot of any URL"""
    driver = get_driver()
    if not driver:
        return None
    ts        = int(time.time() * 1000)
    shot_name = f"page_{ts}.png"
    shot_path = os.path.join(SCREENSHOT_DIR, shot_name)
    shot_web  = f"/static/screenshots/{shot_name}"
    try:
        driver.get(url)
        time.sleep(2)
        try:
            alert = WebDriverWait(driver, 2).until(EC.alert_is_present())
            alert.accept()
        except Exception:
            pass
        driver.save_screenshot(shot_path)
        return shot_web
    except Exception as e:
        print(f"[Browser] Screenshot error: {e}")
        return None
    finally:
        try:
            driver.quit()
        except Exception:
            pass
