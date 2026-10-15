"""Records a walkthrough of the running dashboard to demo/ui.webm (system Chromium, headless).

    uv run streamlit run ui/app.py --server.headless true &   # on :8501
    uv run python demo/record_ui.py
"""
import pathlib
import shutil

from playwright.sync_api import sync_playwright

URL = "http://localhost:8501"
OUT = pathlib.Path(__file__).resolve().parent


def settle(page, text):
    page.get_by_text(text, exact=False).first.wait_for(timeout=60000)
    page.wait_for_timeout(2500)  # charts finish drawing after the text appears


def scroll(page, steps=6, px=350, pause=900):
    for _ in range(steps):
        page.mouse.wheel(0, px)
        page.wait_for_timeout(pause)


def pick(page, option):
    page.locator("[data-testid='stSelectbox']").first.click()
    page.get_by_role("option", name=option).click()
    page.wait_for_timeout(3000)


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=shutil.which("chromium"), headless=True)
    ctx = browser.new_context(viewport={"width": 1600, "height": 900}, record_video_dir=str(OUT / "video_tmp"),
                              record_video_size={"width": 1600, "height": 900})
    page = ctx.new_page()

    page.goto(f"{URL}/"); settle(page, "Captures"); scroll(page, 4)
    page.goto(f"{URL}/traffic"); settle(page, "Packets per minute"); scroll(page, 5)
    page.mouse.wheel(0, -3000); page.wait_for_timeout(800)
    pick(page, "ctu54 · Virut"); scroll(page, 5)
    page.goto(f"{URL}/packets"); settle(page, "Display filter"); page.wait_for_timeout(1500)
    page.get_by_placeholder("e.g. SYN").fill("6667"); page.keyboard.press("Enter"); page.wait_for_timeout(3000)
    page.get_by_placeholder("e.g. SYN").fill("SYN"); page.keyboard.press("Enter"); page.wait_for_timeout(3000)
    page.goto(f"{URL}/detection"); settle(page, "Per capture"); scroll(page, 3)
    page.mouse.wheel(0, -3000); page.wait_for_timeout(800)
    page.get_by_text("Unseen capture", exact=False).first.click(); page.wait_for_timeout(3000); scroll(page, 3)
    page.get_by_text("auc_pr", exact=True).first.click(); page.wait_for_timeout(2500); scroll(page, 5)
    page.goto(f"{URL}/hunt"); settle(page, "Threat hunt"); page.wait_for_timeout(2000)
    pick(page, "ctu54 · Virut"); page.wait_for_timeout(2000)

    video = page.video.path()
    ctx.close()
    browser.close()

shutil.move(video, OUT / "ui.webm")
shutil.rmtree(OUT / "video_tmp", ignore_errors=True)
print(f"saved {OUT / 'ui.webm'}")
