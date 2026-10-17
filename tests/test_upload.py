"""End-to-end check of the "Analyse a capture" page: uploads a capture in a real browser, waits for all five pipeline
steps, and checks the results render. Needs the cluster running and the trained model (./run_pipeline.sh spark).

    uv run python tests/test_upload.py [capture file]      # default: data/test/office_slice.pcapng.gz
"""
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
CAPTURE = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "data/test/office_slice.pcapng.gz")
PORT = 8598

server = subprocess.Popen(["streamlit", "run", "ui/app.py", "--server.headless", "true", "--server.port", str(PORT),
                           "--browser.gatherUsageStats", "false"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://localhost:{PORT}/_stcore/health")
            break
        except OSError:
            time.sleep(1)
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=shutil.which("chromium"), headless=True)
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        page.goto(f"http://localhost:{PORT}/")
        page.get_by_text("Analyse a capture").first.wait_for(timeout=60000)
        page.locator("[data-testid='stFileUploader'] input[type='file']").set_input_files(str(CAPTURE))
        analyse = page.get_by_role("button", name="Analyse", exact=True)
        for _ in range(120):  # enabled once the upload has reached the server
            if analyse.is_enabled():
                break
            page.wait_for_timeout(500)
        t0 = time.time()
        analyse.click()
        page.get_by_text("Results ·").first.wait_for(timeout=20 * 60 * 1000)
        page.wait_for_timeout(4000)
        assert page.get_by_text("failed after").count() == 0, "a step failed"
        assert page.get_by_text("done in").count() == 5, f"expected 5 finished steps, saw {page.get_by_text('done in').count()}"
        errors = page.locator("[data-testid='stException']").all_inner_texts()
        assert not errors, errors
        (ROOT / "demo/screens").mkdir(parents=True, exist_ok=True)
        page.screenshot(path=ROOT / "demo/screens/analyse.png", full_page=True)
        print(f"ok   {CAPTURE.name}: 5 steps done, results shown ({time.time() - t0:.0f}s)")
        browser.close()
finally:
    server.terminate()
