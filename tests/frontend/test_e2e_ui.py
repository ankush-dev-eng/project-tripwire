"""Playwright E2E and 60 FPS Performance Verification for TRIPWIRE Mission Control UI."""

import asyncio
import socket
from pathlib import Path
from typing import Any

import pytest

try:
    from playwright.async_api import async_playwright

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


def _is_server_reachable(host: str = "127.0.0.1", port: int = 8080) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.asyncio
async def test_frontend_e2e_and_fps_stability() -> None:
    """Verify 0 console errors, view transitions, 60 FPS rendering, and layout stability."""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright is not installed in the active environment.")

    if not _is_server_reachable():
        pytest.skip("Mission Control server (http://127.0.0.1:8080) is not reachable.")

    trace_dir = Path("tests/frontend")
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_path = trace_dir / "trace.zip"

    console_errors: list[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            record_video_dir=str(trace_dir / "videos"),
        )
        await context.tracing.start(screenshots=True, snapshots=True, sources=True)

        page = await context.new_page()

        # Monitor console errors
        def on_console(msg: Any) -> None:
            if msg.type == "error":
                console_errors.append(msg.text)

        page.on("console", on_console)

        # 1. Load Mission Control root
        resp = await page.goto("http://127.0.0.1:8080/", wait_until="networkidle")
        assert resp is not None and resp.status == 200, (
            f"Failed to load UI, status: {resp.status if resp else 'None'}"
        )

        # Verify page title and header
        title = await page.title()
        assert "TRIPWIRE" in title or "Tripwire" in title

        # Verify branding element
        content = await page.content()
        assert "TRIPWIRE" in content

        # 2. Measure Frame Rate (FPS) Stability over 120 animation frames
        fps_data = await page.evaluate(
            """() => new Promise((resolve) => {
                const times = [];
                let frameCount = 0;
                function frame(now) {
                    times.push(now);
                    frameCount++;
                    if (frameCount < 120) {
                        requestAnimationFrame(frame);
                    } else {
                        const deltas = [];
                        for (i = 1; i < times.length; i++) {
                            deltas.push(times[i] - times[i-1]);
                        }
                        const avgDelta = deltas.reduce((a, b) => a + b, 0) / deltas.length;
                        const fps = 1000 / avgDelta;
                        resolve({
                            fps: Math.round(fps),
                            avgDelta: avgDelta,
                            maxDelta: Math.max(...deltas),
                            frameCount: times.length
                        });
                    }
                }
                requestAnimationFrame(frame);
            })"""
        )

        avg_fps = fps_data["fps"]
        assert avg_fps >= 50, f"Frame rate dropped below 50 fps: {avg_fps} fps (target ~60 fps)"

        # 3. Test Navigation Across Views
        nav_buttons = await page.query_selector_all("nav button")
        assert len(nav_buttons) >= 5, f"Expected navigation buttons, found {len(nav_buttons)}"

        # Click through each view and verify rendering
        for btn in nav_buttons:
            btn_text = await btn.inner_text()
            await btn.click()
            await page.wait_for_timeout(100)  # 100ms smooth transition
            view_content = await page.content()
            assert len(view_content) > 500, f"View {btn_text} rendered empty"

        # 4. Measure Cumulative Layout Shift (CLS)
        cls_score = await page.evaluate(
            """() => new Promise((resolve) => {
                let cls = 0;
                const observer = new PerformanceObserver((entryList) => {
                    for (const entry of entryList.getEntries()) {
                        if (!entry.hadRecentInput) {
                            cls += entry.value;
                        }
                    }
                });
                observer.observe({type: 'layout-shift', buffered: true});
                setTimeout(() => {
                    observer.disconnect();
                    resolve(cls);
                }, 500);
            })"""
        )

        assert cls_score < 0.1, f"CLS score too high: {cls_score} (target < 0.1)"

        # 5. Stop Tracing & Save
        await context.tracing.stop(path=str(trace_path))
        await context.close()
        await browser.close()

    # 6. Verify zero console errors
    assert len(console_errors) == 0, "Detected console errors during E2E navigation:\n" + "\n".join(
        console_errors
    )


if __name__ == "__main__":
    asyncio.run(test_frontend_e2e_and_fps_stability())
    print("SUCCESS: Playwright E2E and 60 FPS verification passed!")
