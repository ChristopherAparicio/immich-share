#!/usr/bin/env python3
"""Progressive Immich Share download benchmark.

The URL and password are prompted without echo when omitted. Response bodies
are read and discarded without being written to disk. Use only a temporary,
non-sensitive test album.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import getpass
import http.cookiejar
import json
import math
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field


DOWNLOAD_PATH_RE = re.compile(
    r"^/share/(?:photo|video)/([A-Za-z0-9_-]{8,128})/"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/original/?$"
)


@dataclass
class Stats:
    bytes_read: int = 0
    started: int = 0
    completed: int = 0
    limited: int = 0
    errors: int = 0
    unexpected: int = 0
    ttfb: list[float] = field(default_factory=list)

    def merge(self, other: "Stats") -> None:
        self.bytes_read += other.bytes_read
        self.started += other.started
        self.completed += other.completed
        self.limited += other.limited
        self.errors += other.errors
        self.unexpected += other.unexpected
        self.ttfb.extend(other.ttfb)


def percentile(values: list[float], p: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * p) - 1)
    return ordered[index]


def unlock(origin: str, key: str, password: str, context: ssl.SSLContext) -> str:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=context),
    )
    payload = json.dumps({"key": key, "password": password}).encode()
    request = urllib.request.Request(
        origin + "/share/unlock",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError(f"unlock returned HTTP {response.status}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"unable to unlock share: {exc}") from exc

    cookie = "; ".join(f"{item.name}={item.value}" for item in jar)
    if not cookie:
        raise RuntimeError("IPP returned no session cookie")
    return cookie


def worker(url: str, cookie: str, deadline: float, context: ssl.SSLContext) -> Stats:
    stats = Stats()
    headers = {
        "Cookie": cookie,
        "User-Agent": "immich-share-benchmark/1",
        "Accept": "*/*",
    }
    while time.monotonic() < deadline:
        stats.started += 1
        started = time.monotonic()
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            timeout = max(2.0, min(15.0, deadline - time.monotonic()))
            with urllib.request.urlopen(
                request, timeout=timeout, context=context
            ) as response:
                stats.ttfb.append(time.monotonic() - started)
                content_type = response.headers.get("Content-Type", "").lower()
                # IPP may omit Content-Disposition when shared-asset metadata has
                # no original filename. The path is already strictly validated;
                # rejecting text and JSON detects gallery/error responses without
                # rejecting valid binary media.
                if content_type.startswith("text/") or "json" in content_type:
                    stats.unexpected += 1
                    response.read(64 * 1024)
                    return stats

                reached_eof = True
                while time.monotonic() < deadline:
                    chunk = response.read(256 * 1024)
                    if not chunk:
                        break
                    stats.bytes_read += len(chunk)
                else:
                    reached_eof = False
                if reached_eof:
                    stats.completed += 1
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                stats.limited += 1
                retry = exc.headers.get("Retry-After")
                try:
                    pause = min(5.0, max(0.25, float(retry))) if retry else 1.0
                except ValueError:
                    pause = 1.0
                time.sleep(min(pause, max(0.0, deadline - time.monotonic())))
            elif exc.code in (401, 403, 404):
                stats.unexpected += 1
                return stats
            else:
                stats.errors += 1
                time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
        except (TimeoutError, urllib.error.URLError, OSError):
            # A timeout at the end of a level is expected. Earlier timeouts remain
            # visible in the counter and should be correlated with VPS/NAS logs.
            if time.monotonic() < deadline - 0.5:
                stats.errors += 1
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    return stats


def parse_levels(raw: str) -> list[int]:
    try:
        levels = [int(value) for value in raw.split(",")]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected: 1,2,4,6,8,12") from exc
    if not levels or any(value < 1 or value > 32 for value in levels):
        raise argparse.ArgumentTypeError("each level must be between 1 and 32")
    if levels != sorted(set(levels)):
        raise argparse.ArgumentTypeError("levels must be unique and increasing")
    return levels


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Progressive Immich Share download throughput benchmark"
    )
    parser.add_argument(
        "url", nargs="?", help=".../original URL (otherwise prompted without echo)"
    )
    parser.add_argument(
        "--levels", type=parse_levels, default=parse_levels("1,2,4,6,8,12")
    )
    parser.add_argument(
        "--duration", type=int, default=30, help="seconds per level (10–300)"
    )
    parser.add_argument(
        "--cooldown", type=int, default=5, help="pause between levels (0–60 s)"
    )
    parser.add_argument("--yes", action="store_true", help="confirm the load test")
    parser.add_argument("--allow-http", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if not 10 <= args.duration <= 300 or not 0 <= args.cooldown <= 60:
        parser.error("duration must be 10–300 and cooldown must be 0–60")

    url = args.url or getpass.getpass("Download .../original URL (hidden): ")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" and not (args.allow_http and parsed.scheme == "http"):
        parser.error("HTTPS is required")
    match = DOWNLOAD_PATH_RE.fullmatch(parsed.path)
    if not match or parsed.username or parsed.password:
        parser.error("expected URL: /share/photo|video/<key>/<UUID>/original")
    origin = f"{parsed.scheme}://{parsed.netloc}"

    total_seconds = sum(args.duration for _ in args.levels)
    total_seconds += args.cooldown * max(0, len(args.levels) - 1)
    print(
        f"Levels {','.join(map(str, args.levels))} × {args.duration}s "
        f"(~{total_seconds // 60} min {total_seconds % 60}s)."
    )
    print("No file will be retained. Monitor the VPS and NAS at the same time.")
    if not args.yes:
        confirmation = input("Type BENCHMARK to continue: ")
        if confirmation != "BENCHMARK":
            print("Canceled.")
            return 2

    password = getpass.getpass("Share password (hidden): ")
    context = ssl.create_default_context()
    try:
        cookie = unlock(origin, match.group(1), password, context)
    finally:
        password = ""

    print()
    print(
        "conc.  throughput   started  done   429  errors   unexpected response  TTFB p95"
    )
    print(
        "-----  -----------  -------  -----  ---  -------  -------------------  --------"
    )

    for index, concurrency in enumerate(args.levels):
        started = time.monotonic()
        deadline = started + args.duration
        aggregate = Stats()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [
                pool.submit(worker, url, cookie, deadline, context)
                for _ in range(concurrency)
            ]
            for future in concurrent.futures.as_completed(futures):
                aggregate.merge(future.result())
        elapsed = max(0.001, time.monotonic() - started)
        mbps = aggregate.bytes_read * 8 / elapsed / 1_000_000
        p95 = percentile(aggregate.ttfb, 0.95)
        p95_text = "-" if math.isnan(p95) else f"{p95 * 1000:.0f}ms"
        print(
            f"{concurrency:>5}  {mbps:>9.1f}Mb/s  {aggregate.started:>8}  "
            f"{aggregate.completed:>5}  {aggregate.limited:>3}  "
            f"{aggregate.errors:>7}  {aggregate.unexpected:>17}  {p95_text:>8}"
        )
        if aggregate.unexpected:
            print(
                "Rejected or non-media response: verify the password and URL.",
                file=sys.stderr,
            )
            return 1
        if index + 1 < len(args.levels) and args.cooldown:
            time.sleep(args.cooldown)

    print("\nChoose a ceiling one level below saturation or the first errors.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
