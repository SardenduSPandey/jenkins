import time
from playwright.sync_api import sync_playwright
from zapv2 import ZAPv2
import sys
import json

# -------------------------
# ZAP DAEMON INSTRUCTIONS
# -------------------------
# Before running this script, you must start ZAP in daemon mode.
# Open your terminal or command prompt and navigate to the ZAP installation directory.
#
# On Windows:
# > zap.bat -daemon -port 8091 -host 127.0.0.1
#
# On Linux/macOS:
# $ ./zap.sh -daemon -port 8091 -host 127.0.0.1
# -------------------------


# -------------------------
# CONFIG
# -------------------------
ZAP_PROXY = 'http://127.0.0.1:8091'
TARGET_URL = 'https://example.com/dashboard'
BASE_SITE = 'https://example.com'
CONTEXT_NAME = 'AuthenticatedContext'
SESSION_NAME = 'authSession'
USER_NAME = 'auth_user'

# Patterns to include/exclude (regex)
INCLUDE_PATTERN = r'https://example\.com/.*'
EXCLUDE_BLOG_PATTERN = r'https://example\.com/blog.*'
EXTERNAL_EXCLUDES = [
    r'.*mastodon\.social.*',
    r'.*facebook\.com.*',
    r'.*twitter\.com.*',
    r'.*googlesyndication.*',
    r'.*sassy-social-share.*'
]

# -------------------------
# 1. Playwright: load saved session and extract cookies
# -------------------------
print("🔐 Launching Playwright and loading saved session (auth.json)...")
try:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(storage_state="auth.json")
        page = context.new_page()
        page.goto(TARGET_URL)

        # Simple login validation — adjust text/assertion to your app if needed
        page_text = page.content().lower()
        if "login" in page.url.lower() or "sign in" in page_text:
            print("❌ Login failed - session might be expired or invalid. Please refresh auth.json with a headed run.")
            browser.close()
            sys.exit(1)

        cookies = context.cookies()
        print(f"✅ Logged in via saved session. Extracted {len(cookies)} cookies.")
        browser.close()
except FileNotFoundError:
    print("❌ Error: auth.json not found. Please run the initial authentication script to generate it.")
    sys.exit(1)
except Exception as e:
    print(f"❌ An unexpected error occurred during Playwright execution: {e}")
    sys.exit(1)


# -------------------------
# 2. Connect to ZAP and configure context
# -------------------------
print("⚙️ Connecting to ZAP...")
zap = ZAPv2(proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

# Quick connectivity check
try:
    version = zap.core.version
    print(f"🔌 Connected to ZAP (version: {version})")
except Exception as e:
    print(f"❌ Unable to connect to ZAP. Error: {e}")
    print("👉 Please ensure ZAP is running in daemon mode before executing this script.")
    print("   On Windows: zap.bat -daemon -port 8091 -host 127.0.0.1")
    print("   On Linux/macOS: ./zap.sh -daemon -port 8091 -host 127.0.0.1")
    sys.exit(1)

# --- AJAX Spider Configuration ---
print("🔧 Configuring AJAX Spider to use a single browser...")
zap.ajaxSpider.set_option_number_of_browsers(1)
# --- End of AJAX Spider Configuration ---

# Create context (ignore error if it already exists)
try:
    zap.context.new_context(CONTEXT_NAME)
except Exception:
    pass

# Include only the /a/* paths (in-scope)
zap.context.include_in_context(CONTEXT_NAME, INCLUDE_PATTERN)

# Try to exclude from context (some versions have it); safe to ignore errors
try:
    zap.context.exclude_from_context(CONTEXT_NAME, EXCLUDE_BLOG_PATTERN)
except Exception:
    pass

# Spider-level excludes for blog + common externals (always works)
zap.spider.exclude_from_scan(EXCLUDE_BLOG_PATTERN)
for pat in EXTERNAL_EXCLUDES:
    zap.spider.exclude_from_scan(pat)


# Get numeric context id (required by some API calls)
context_info = zap.context.context(CONTEXT_NAME)
context_id = context_info.get('id')
if not context_id:
    print(f"❌ Could not find context with name '{CONTEXT_NAME}'.")
    sys.exit(1)
print(f"📦 Using ZAP Context '{CONTEXT_NAME}' id={context_id}")


# -------------------------
# 3. Create HTTP session, User, and inject cookies
# -------------------------
print("🍪 Creating ZAP HTTP session and injecting cookies...")
try:
    zap.httpsessions.create_empty_session(CONTEXT_NAME, SESSION_NAME)
except Exception:
    try:
        zap.httpsessions.create_empty_session(BASE_SITE, SESSION_NAME)
    except Exception:
        pass

for c in cookies:
    name = c.get('name')
    value = c.get('value')
    if not name:
        continue
    try:
        zap.httpsessions.add_session_token(CONTEXT_NAME, name)
    except Exception:
        try:
            zap.httpsessions.add_session_token(BASE_SITE, name)
        except Exception:
            pass
    try:
        zap.httpsessions.set_session_token_value(CONTEXT_NAME, SESSION_NAME, name, value)
    except Exception:
        try:
            zap.httpsessions.set_session_token_value(BASE_SITE, SESSION_NAME, name, value)
        except Exception as e:
            print(f"⚠️ Warning: failed to set token value for {name}: {e}")

try:
    zap.httpsessions.set_active_session(BASE_SITE, SESSION_NAME)
except Exception:
    try:
        zap.httpsessions.set_active_session(CONTEXT_NAME, SESSION_NAME)
    except Exception:
        print("⚠️ Warning: could not explicitly set active session.")
print("✅ Cookies injected.")

# --- Create a User and Enable Forced User Mode (Crucial for AJAX Spider) ---
print(f"👤 Creating user '{USER_NAME}' in context and enabling Forced User Mode...")
try:
    zap.users.new_user(contextid=context_id, name=USER_NAME)
except Exception:
    pass  # User might already exist, which is fine

# Find the user ID
user_id = None
try:
    # The zapv2 client returns a list of dictionaries directly, not a JSON string.
    users_list = zap.users.users_list(contextid=context_id)
    for user in users_list:
        if user.get('name') == USER_NAME:
            user_id = user.get('id')
            break
except Exception as e:
    print(f"❌ Error processing users list from ZAP. Raw response: {zap.users.users_list(contextid=context_id)}")
    print(f"   Error details: {e}")
    sys.exit(1)

if not user_id:
    print(f"❌ Could not find user ID for user '{USER_NAME}'.")
    sys.exit(1)
print(f"✅ Found user ID: {user_id}")

# Enable forced user mode
zap.forcedUser.set_forced_user_mode_enabled(True)
zap.forcedUser.set_forced_user(contextid=context_id, userid=user_id)
print("✅ Forced User Mode is now ON. All scans will run as the authenticated user.")
# --------------------------------------------------------------------------

# -------------------------
# 4. Spider + AJAX Spider + Active scan (authenticated)
# -------------------------
print("🔍 Starting standard spider (as authenticated user)...")
try:
    zap.urlopen(TARGET_URL)
except Exception:
    pass

spider_id = zap.spider.scan_as_user(contextid=context_id, userid=user_id, url=TARGET_URL)

while True:
    status = zap.spider.status(spider_id)
    try:
        sval = int(status)
    except Exception:
        sval = 0
    print(f"Standard Spider: {sval}%")
    if sval >= 100:
        break
    time.sleep(3)
print("✅ Standard Spider finished.")
time.sleep(2)

print("🌐 Starting AJAX Spider for deep crawling (as authenticated user)...")
zap.ajaxSpider.scan_as_user(contextname=CONTEXT_NAME, username=USER_NAME, url=TARGET_URL)

while zap.ajaxSpider.status == 'running':
    print("AJAX Spider: running...")
    time.sleep(5)
print("✅ AJAX Spider finished.")
time.sleep(2)

print("⚡ Starting active scan (as authenticated user)...")
scan_id = zap.ascan.scan_as_user(url=TARGET_URL, contextid=context_id, userid=user_id)

while True:
    status = zap.ascan.status(scan_id)
    try:
        sval = int(status)
    except Exception:
        sval = 0
    print(f"Active scan: {sval}%")
    if sval >= 100:
        break
    time.sleep(10)
print("✅ Active scan completed.")


# -------------------------
# 5. Generate HTML report
# -------------------------
print("📄 Generating HTML report...")
try:
    report_html = zap.core.htmlreport()
    with open("zap_report.html", "w", encoding="utf-8") as f:
        f.write(report_html)
    print("✅ Report saved: zap_report.html")
except Exception as e:
    print(f"❌ Failed to generate report: {e}")
    sys.exit(1)
finally:
    # It's good practice to turn off forced user mode when you're done
    print("⚫ Disabling Forced User Mode.")
    zap.forcedUser.set_forced_user_mode_enabled(False)

