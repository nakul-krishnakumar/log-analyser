"""UI smoke test: starts the dashboard, loads every page in headless Chromium, fails on any Streamlit exception,
and saves a full-page screenshot of each to demo/screens/. Needs results/dashboard (run the pipeline first).

    uv run python tests/test_ui.py
"""
import pathlib
import shutil
import subprocess
import time
import urllib.request

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
PORT = 8599
PAGES = [("", "start", "Which file do I upload?"), ("overview", "overview", "Captures"), ("traffic", "traffic", "Packets per minute"), ("packets", "packets", "Display filter"),
         ("detection", "detection", "Per capture"), ("hunt", "hunt", "Threat hunt")]

server = subprocess.Popen(["streamlit", "run", "ui/app.py", "--server.headless", "true", "--server.port", str(PORT),
                           "--browser.gatherUsageStats", "false"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://localhost:{PORT}/_stcore/health")
            break
        except OSError:
            time.sleep(1)
    (ROOT / "demo/screens").mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=shutil.which("chromium"), headless=True)
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        for path, name, marker in PAGES:
            page.goto(f"http://localhost:{PORT}/{path}")
            page.get_by_text(marker).first.wait_for(timeout=60000)
            page.wait_for_timeout(4000)
            assert page.get_by_text("Page not found").count() == 0, f"{name}: page not found"
            errors = page.locator("[data-testid='stException']").all_inner_texts()
            assert not errors, f"{name}: {errors}"
            page.screenshot(path=ROOT / f"demo/screens/{name}.png", full_page=True)
            print(f"ok   {name}")
        browser.close()
finally:
    server.terminate()
