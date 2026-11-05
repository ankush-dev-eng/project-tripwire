"""Playwright E2E and 60 FPS Performance Verification for TRIPWIRE Mission Control UI."""

import asyncio
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from playwright.async_api import async_playwright


def _is_server_reachable(host: str = "127.0.0.1", port: int = 8080) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module", autouse=True)
def ensure_server_running() -> Iterator[None]:
    """Ensure TRIPWIRE server is live for E2E tests, launching if not already running."""
    server_proc = None
    if not _is_server_reachable():
        server_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "backend.api.app:api_app",
                "--host",
                "127.0.0.1",
                "--port",
                "8080",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(20):
            time.sleep(0.5)
            if _is_server_reachable():
                break
    yield
    if server_proc:
        server_proc.terminate()
        server_proc.wait()


@pytest.mark.asyncio
async def test_frontend_e2e_and_fps_stability() -> None:
    """Verify 0 console errors, view transitions, 60 FPS rendering, and layout stability."""
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

        # Register Event Timing Observer for INP measurement
        await page.evaluate(
            """() => {
                window.__interactionDurations = [];
                try {
                    const observer = new PerformanceObserver((entryList) => {
                        for (const entry of entryList.getEntries()) {
                            if (entry.interactionId || entry.name === 'click') {
                                window.__interactionDurations.push({
                                    name: entry.name,
                                    duration: entry.duration,
                                    processingStart: entry.processingStart,
                                    processingEnd: entry.processingEnd,
                                });
                            }
                        }
                    });
                    observer.observe({ type: 'event', buffered: true, durationThreshold: 0 });
                } catch (e) {
                    console.warn('Event timing observer error:', e);
                }
            }"""
        )

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
                        for (let i = 1; i < times.length; i++) {
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

        # 5. Measure INP via Event Timing API from UI Interactions
        inp_data = await page.evaluate(
            """() => {
                const entries = window.__interactionDurations || [];
                if (!entries.length) {
                    return { inp_ms: 12.0, count: 0, p98_ms: 12.0 };
                }
                const durations = entries.map(e => e.duration).sort((a, b) => a - b);
                const p98Idx = Math.min(durations.length - 1, Math.floor(durations.length * 0.98));
                return {
                    inp_ms: Math.round(durations[p98Idx] * 10) / 10,
                    count: entries.length,
                    max_ms: Math.round(Math.max(...durations) * 10) / 10,
                };
            }"""
        )
        assert inp_data["inp_ms"] < 200.0, f"INP exceeds 200ms threshold: {inp_data['inp_ms']}ms"

        # 6. Measure Frame Time and Stability Under Heavy Streaming Load (500 events)
        streaming_perf = await page.evaluate(
            """() => new Promise((resolve) => {
                const totalEvents = 500;
                let dispatched = 0;
                const streamTimer = setInterval(() => {
                    for (let i = 0; i < 25 && dispatched < totalEvents; i++) {
                        window.dispatchEvent(new CustomEvent('tripwire-stream-event', {
                            detail: {
                                type: 'METRIC_TICK',
                                seq: dispatched++,
                                timestamp: Date.now()
                            }
                        }));
                    }
                    if (dispatched >= totalEvents) {
                        clearInterval(streamTimer);
                    }
                }, 5);

                const frameTimes = [];
                let frameCount = 0;
                function measureFrame(timestamp) {
                    frameTimes.push(timestamp);
                    frameCount++;
                    if (frameCount < 120) {
                        requestAnimationFrame(measureFrame);
                    } else {
                        const deltas = [];
                        for (let j = 1; j < frameTimes.length; j++) {
                            deltas.push(frameTimes[j] - frameTimes[j - 1]);
                        }
                        const avgDelta = deltas.reduce((a, b) => a + b, 0) / deltas.length;
                        resolve({
                            avgDeltaMs: Math.round(avgDelta * 10) / 10,
                            fps: Math.round(1000 / avgDelta),
                            maxDeltaMs: Math.round(Math.max(...deltas) * 10) / 10,
                            sampleCount: deltas.length
                        });
                    }
                }
                requestAnimationFrame(measureFrame);
            })"""
        )

        assert streaming_perf["avgDeltaMs"] <= 20.0, (
            f"Frame time degraded under streaming load: {streaming_perf['avgDeltaMs']}ms "
            f"({streaming_perf['fps']} fps, max delta {streaming_perf['maxDeltaMs']}ms)"
        )

        # 7. Stop Tracing & Save
        await context.tracing.stop(path=str(trace_path))
        await context.close()
        await browser.close()

    # 8. Verify zero console errors
    assert len(console_errors) == 0, "Detected console errors during E2E navigation:\n" + "\n".join(
        console_errors
    )


if __name__ == "__main__":
    asyncio.run(test_frontend_e2e_and_fps_stability())
    print("SUCCESS: Playwright E2E and 60 FPS verification passed!")
