#!/usr/bin/env python3
"""
scanner.py — Async numeric ID enumerator for CTF file discovery.

Brute-forces integer IDs on endpoints like:
    https://DVWA.com/site/downloadactivityfile?id=1176403

Identifies which ID(s) return a real file vs error/empty responses.

AUTHORIZED TESTING ONLY. Do not use against systems you don't own.

Usage:
    python scanner.py -u "https://DVWA.com/site/downloadactivityfile" \
                      --start 1 --end 2000000 -c 50 -o results
"""

import asyncio
import aiohttp
import argparse
import json
import hashlib
import random
import time
import sys
import signal
from dataclasses import dataclass, asdict
from typing import Optional
from datetime import datetime


# ──────────────────────────────────────────────────────────────────────────────
# Data structure for one result
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class HitResult:
    """Everything we know about a numeric ID that returned something interesting."""
    id: int                      # The numeric ID that was tested
    url: str                     # Full URL with ?id=N
    status: int                  # HTTP status code
    size: int                    # Response body size in bytes
    content_type: str            # Content-Type header (tells us file type)
    content_disposition: str     # e.g. attachment; filename="flag.txt"
    redirect_location: str       # Location header if a redirect
    classification: str          # Our verdict
    response_time_ms: float      # How long the request took
    body_preview: str            # First 120 chars of body (useful for CTF flags)
    error: str = ""              # Error message if connection failed


# ──────────────────────────────────────────────────────────────────────────────
# Baseline fingerprint (detects soft-404 / custom error pages)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Baseline:
    """
    What the server returns for IDs that definitely don't exist.
    We probe with IDs like 0, -1, 99999999 to learn the "not found" signature.
    """
    status: int = 0
    size: int = 0
    body_hash: str = ""
    content_type: str = ""
    size_tolerance: float = 0.05     # 5% size variance still counts as a match

    def is_404_like(self, status: int, size: int, body_hash: str) -> bool:
        """
        Return True if this response looks like the server's "not found" response.

        Three ways to match:
        1. Exact body hash → same HTML error page every time (most reliable)
        2. Same status code AND nearly identical body size → very likely same page
        3. If baseline status is 404 and response is also 404 → straightforward
        """
        # Exact body match — definitive soft-404
        if self.body_hash and body_hash == self.body_hash:
            return True

        # Same status + size within tolerance
        if self.status == status and self.size > 0:
            diff = abs(size - self.size) / max(self.size, 1)
            if diff <= self.size_tolerance:
                return True

        return False


# ──────────────────────────────────────────────────────────────────────────────
# Main scanner class
# ──────────────────────────────────────────────────────────────────────────────

class IDScanner:
    """
    Enumerates integer IDs on a target URL's query parameter.

    Flow:
      1. Probe 5 known-bad IDs  → build Baseline (what "not found" looks like)
      2. Stream IDs start..end  → semaphore-limited async requests
      3. Filter each response against the baseline
      4. Double-verify any hit that looks real
      5. Save results.txt + results.json
    """

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
        batch_print: int = 1000,        # Print progress every N IDs
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

        # Runtime counters (updated by worker coroutines)
        self.baseline = Baseline()
        self.semaphore: asyncio.Semaphore = None        # type: ignore
        self.hits: list[HitResult] = []                 # Interesting results
        self.checked = 0
        self.found = 0
        self.errors = 0
        self.total = end - start + 1
        self._stop = False
        self._progress_lock = asyncio.Lock()            # Protects counter updates

    # ── URL builder ───────────────────────────────────────────────────────────

    def build_url(self, id_val: int) -> str:
        """Construct the full URL for a given numeric ID."""
        return f"{self.base_url}?{self.param}={id_val}"

    # ── Low-level HTTP fetch ──────────────────────────────────────────────────

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> tuple[int, int, str, str, str, str, str, float]:
        """
        Perform one GET request. Returns a tuple of:
            (status, body_size, content_type, content_disposition,
             redirect_location, body_hash, body_preview, elapsed_ms)

        On connection error: status=0, everything else empty.
        """
        start = time.monotonic()
        try:
            async with session.get(
                url,
                allow_redirects=False,   # Handle redirects ourselves
                ssl=self.verify_ssl,
            ) as resp:
                elapsed_ms = (time.monotonic() - start) * 1000
                body = await resp.read()

                # Decode a small preview for flag hunting (CTF!)
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
                    preview[:120],          # Trim to 120 chars for display
                    round(elapsed_ms, 1),
                )

        except asyncio.TimeoutError:
            elapsed_ms = (time.monotonic() - start) * 1000
            return 0, 0, "", "", "", "", "TIMEOUT", round(elapsed_ms, 1)

        except aiohttp.ClientError as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return 0, 0, "", "", "", "", str(exc)[:80], round(elapsed_ms, 1)

    async def _fetch_with_retry(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> tuple[int, int, str, str, str, str, str, float]:
        """Retry wrapper: exponential backoff on errors, pause on 429."""
        for attempt in range(self.retry_limit + 1):
            result = await self._fetch(session, url)
            status = result[0]

            if status == 429:
                # Server said slow down — respect that
                wait = self.delay_on_429 * (attempt + 1)
                print(f"\n  [⏳] Rate limited. Waiting {wait:.0f}s…", flush=True)
                await asyncio.sleep(wait)
                continue

            if status == 0 and attempt < self.retry_limit:
                # Connection error — short backoff
                await asyncio.sleep(0.3 * (attempt + 1))
                continue

            return result

        return 0, 0, "", "", "", "", "ALL_RETRIES_FAILED", 0.0

    # ── Baseline establishment ────────────────────────────────────────────────

    async def establish_baseline(self, session: aiohttp.ClientSession) -> None:
        """
        Probe 5 IDs that almost certainly don't exist to learn what
        the server's "not found" response looks like.

        We use:
          - 0          (most APIs reject this)
          - -1         (negative — always invalid)
          - 999999997, 999999998, 999999999  (far beyond typical ranges)

        From these we extract the "not found" fingerprint: status + size + hash.
        """
        print("[*] Probing baseline (what does 'not found' look like?)…")

        # IDs that should definitely not exist
        probe_ids = [0, -1, 999_999_997, 999_999_998, 999_999_999]

        probe_statuses = []
        probe_sizes    = []
        probe_hashes   = []

        for pid in probe_ids:
            url = self.build_url(pid)
            status, size, ct, cd, loc, body_hash, preview, _ = \
                await self._fetch(session, url)
            probe_statuses.append(status)
            probe_sizes.append(size)
            probe_hashes.append(body_hash)
            await asyncio.sleep(0.15)   # Be gentle during probing

        # Dominant status = what most probes returned
        dominant_status = max(set(probe_statuses), key=probe_statuses.count)
        avg_size = int(sum(probe_sizes) / len(probe_sizes))

        # If all hashes agree we have a perfect fingerprint
        unique_hashes = set(probe_hashes)
        best_hash = probe_hashes[0] if len(unique_hashes) == 1 else ""

        self.baseline = Baseline(
            status=dominant_status,
            size=avg_size,
            body_hash=best_hash,
        )

        print(
            f"[+] Baseline → status={dominant_status}  "
            f"size≈{avg_size}B  "
            f"hash={'fixed ✓' if best_hash else 'varies (using size tolerance)'}"
        )

    # ── Classification ────────────────────────────────────────────────────────

    def classify(
        self,
        status: int,
        size: int,
        body_hash: str,
        content_type: str,
        content_disposition: str,
    ) -> str:
        """
        Classify a response into one of these buckets:

        - "hit"          → 200 + different from baseline = REAL FILE  ⭐
        - "soft_404"     → 200 but matches baseline = fake success
        - "forbidden"    → 403 = exists but we can't access it
        - "redirect"     → 3xx = points somewhere else (still interesting!)
        - "not_found"    → clean 404
        - "rate_limited" → 429
        - "server_error" → 5xx
        - "error"        → connection/timeout
        - "other"        → anything else
        """
        if status == 0:
            return "error"

        # Soft-404 check: server returns 200 but it's the error page
        if self.baseline.is_404_like(status, size, body_hash):
            return "soft_404"

        if status == 200:
            # Real file! Extra confidence if server says it's an attachment
            if content_disposition and "attachment" in content_disposition.lower():
                return "hit"    # Server explicitly offers a file download
            if size > 0:
                return "hit"    # Has content and doesn't match the error page
            return "soft_404"   # 200 but empty body = probably an error page too

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

    # ── Single ID check ───────────────────────────────────────────────────────

    async def check_id(
        self,
        session: aiohttp.ClientSession,
        id_val: int,
    ) -> Optional[HitResult]:
        """
        Check one numeric ID.

        Returns a HitResult only for things worth saving;
        silently returns None for "not found" / soft-404.
        """
        async with self.semaphore:
            if self._stop:
                return None

            url = self.build_url(id_val)
            (status, size, content_type, content_disp,
             redirect_loc, body_hash, preview, elapsed) = \
                await self._fetch_with_retry(session, url)

            classification = self.classify(
                status, size, body_hash, content_type, content_disp
            )

            # Only keep interesting results (not "not found" noise)
            keep_classes = {"hit", "forbidden", "redirect", "server_error",
                            "rate_limited", "other", "error"}

            if classification not in keep_classes:
                return None     # Definite miss — discard silently

            # ── Double-verification for real hits ──────────────────────────
            # If we think we found something real, request it again to confirm
            # it wasn't a transient glitch (flaky servers are common in CTFs)
            if self.double_verify and classification in ("hit", "forbidden", "redirect"):
                await asyncio.sleep(0.1)
                (s2, sz2, ct2, cd2, rl2, bh2, pv2, el2) = \
                    await self._fetch_with_retry(session, url)
                clf2 = self.classify(s2, sz2, bh2, ct2, cd2)

                if clf2 != classification:
                    # The two requests disagree — flag as uncertain
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

    # ── Worker coroutine ──────────────────────────────────────────────────────

    async def worker(
        self,
        session: aiohttp.ClientSession,
        queue: asyncio.Queue,
    ) -> None:
        """
        One async worker. Pulls IDs off the shared queue and checks them.
        Multiple workers run concurrently — this is where the speed comes from.

        asyncio means all workers can have requests in-flight at the same time
        without blocking each other, unlike threading which has GIL overhead.
        """
        while not self._stop:
            try:
                id_val = queue.get_nowait()
            except asyncio.QueueEmpty:
                break   # Queue drained — this worker is done

            result = await self.check_id(session, id_val)

            # Thread-safe counter update
            async with self._progress_lock:
                self.checked += 1
                if result:
                    if result.classification in ("hit", "forbidden", "redirect"):
                        self.found += 1
                    if result.classification == "error":
                        self.errors += 1
                    self.hits.append(result)
                    self._print_hit(result)     # Immediately print every find

                # Show rolling progress every N IDs
                if self.checked % self.batch_print == 0 or self.checked == self.total:
                    self._print_progress()

            queue.task_done()

    # ── Progress + hit display ────────────────────────────────────────────────

    def _print_progress(self) -> None:
        """Overwrite the current line with a live progress counter."""
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
        """Print a hit immediately when we find one (above the progress line)."""
        icons = {
            "hit":          "⭐ HIT",
            "forbidden":    "🔒 FORBIDDEN",
            "redirect":     "↪️  REDIRECT",
            "server_error": "💥 SERVER ERR",
            "other":        "❓ UNCERTAIN",
            "error":        "🔌 CONN ERR",
        }
        label = icons.get(r.classification, r.classification.upper())
        print(f"\n  {label}  id={r.id}  status={r.status}  size={r.size}B  "
              f"type={r.content_type}")
        if r.content_disposition:
            print(f"           disposition={r.content_disposition}")
        if r.redirect_location:
            print(f"           → {r.redirect_location}")
        if r.body_preview and r.classification == "hit":
            # Show a snippet — very useful for spotting CTF flags!
            print(f"           preview: {r.body_preview[:100]}")
        print(f"           url: {r.url}", flush=True)

    # ── Main async entry point ────────────────────────────────────────────────

    async def run(self) -> None:
        """Coordinate the full scan."""

        print(f"[*] ID range: {self.start:,} → {self.end:,}  ({self.total:,} IDs)")
        print(f"[*] Endpoint: {self.base_url}?{self.param}=<id>\n")

        # Graceful Ctrl+C handler
        # add_signal_handler is Unix-only — on Windows we use a try/except instead
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGINT, self._handle_interrupt)
        except NotImplementedError:
            pass  # Windows: Ctrl+C is caught by the try/except around asyncio.run() in main()

        # Semaphore: max N requests in-flight at once
        self.semaphore = asyncio.Semaphore(self.concurrency)

        # Shared connection pool across all workers
        connector = aiohttp.TCPConnector(
            limit=self.concurrency + 10,
            ttl_dns_cache=300,      # Cache DNS 5 min — avoids re-resolving every request
            force_close=False,      # Keep-alive: reuse TCP connections
        )
        headers = {"User-Agent": self.user_agent}

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=headers,
        ) as session:

            # Step 1: Learn what "not found" looks like
            await self.establish_baseline(session)

            # Step 2: Fill queue with every ID in the range
            # We use a Queue so workers can pull IDs without coordination
            queue: asyncio.Queue = asyncio.Queue()
            for id_val in range(self.start, self.end + 1):
                await queue.put(id_val)

            print(f"\n[*] Launching {self.concurrency} concurrent workers…\n")
            scan_start = time.monotonic()

            # Step 3: Spawn workers — they all drain the queue concurrently
            num_workers = min(self.concurrency, self.total)
            workers = [
                asyncio.create_task(self.worker(session, queue))
                for _ in range(num_workers)
            ]

            await asyncio.gather(*workers, return_exceptions=True)

        elapsed = time.monotonic() - scan_start
        rps = self.checked / elapsed if elapsed > 0 else 0

        print(f"\n\n{'='*60}")
        print(f"[✓] Scan done in {elapsed:.1f}s  ({rps:.0f} req/s)")
        print(f"    Checked : {self.checked:,}")
        print(f"    Found   : {self.found}")
        print(f"    Errors  : {self.errors}")
        print(f"{'='*60}\n")

        self.save_results()

    def _handle_interrupt(self) -> None:
        """Save partial results and exit cleanly on Ctrl+C."""
        print("\n\n[!] Ctrl+C — saving partial results…")
        self._stop = True
        self.save_results()
        sys.exit(0)

    # ── Output ────────────────────────────────────────────────────────────────

    def save_results(self) -> None:
        """
        Write two output files:
          results.txt  — human-readable, easy to read in a terminal
          results.json — machine-readable, full detail
        """
        txt_path  = f"{self.output_prefix}.txt"
        json_path = f"{self.output_prefix}.json"

        # Sort: hits first, then forbidden, then redirects, then errors
        priority = {
            "hit": 0, "forbidden": 1, "redirect": 2,
            "server_error": 3, "other": 4, "error": 5,
        }
        sorted_hits = sorted(
            self.hits,
            key=lambda r: (priority.get(r.classification, 9), r.id)
        )

        # ── results.txt ──────────────────────────────────────────────────────
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write("  ID Enumeration Scan Results\n")
            f.write("=" * 60 + "\n")
            f.write(f"  Target   : {self.base_url}?{self.param}=<id>\n")
            f.write(f"  Range    : {self.start} → {self.end}\n")
            f.write(f"  Scanned  : {datetime.now().isoformat()}\n")
            f.write(f"  Checked  : {self.checked:,}\n")
            f.write(f"  Found    : {self.found}\n")
            f.write("=" * 60 + "\n\n")

            if not sorted_hits:
                f.write("No interesting results found.\n")
            else:
                for r in sorted_hits:
                    icons = {
                        "hit":       "⭐ REAL FILE",
                        "forbidden": "🔒 FORBIDDEN",
                        "redirect":  "↪  REDIRECT",
                        "other":     "❓ UNCERTAIN",
                        "error":     "🔌 ERROR",
                    }
                    label = icons.get(r.classification, r.classification.upper())
                    f.write(f"[ {label} ]\n")
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

        # ── results.json ─────────────────────────────────────────────────────
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

        print(f"[+] Saved → {txt_path}")
        print(f"[+] Saved → {json_path}")

        # Summary table in terminal
        if sorted_hits:
            print("\n┌─ Interesting Findings " + "─" * 50)
            for r in sorted_hits:
                redir = f"→ {r.redirect_location}" if r.redirect_location else ""
                print(
                    f"│  id={r.id:<12} [{r.status}]  {r.size:>8,}B  "
                    f"{r.content_type:<30} {r.classification}  {redir}"
                )
            print("└" + "─" * 72)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Async numeric ID brute-forcer for CTF file discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan IDs 1 to 2,000,000 at concurrency 50
  python scanner.py -u "https://DVWA.com/site/downloadactivityfile" \\
                    --start 1 --end 2000000 -c 50

  # Already know it's near 1176403 — scan a tight window around it
  python scanner.py -u "https://DVWA.com/site/downloadactivityfile" \\
                    --start 1170000 --end 1180000 -c 30

  # Different query parameter name
  python scanner.py -u "https://target.com/download" --param file_id \\
                    --start 1 --end 50000 -c 40

  # Fast scan, no double-verification (slightly more false positives)
  python scanner.py -u "https://DVWA.com/site/downloadactivityfile" \\
                    --start 1 --end 2000000 -c 100 --no-verify
        """,
    )

    parser.add_argument(
        "-u", "--url", required=True,
        help='Base endpoint URL, e.g. "https://DVWA.com/site/downloadactivityfile"'
    )
    parser.add_argument(
        "--param", default="id",
        help="Query parameter name (default: id)"
    )
    parser.add_argument(
        "--start", type=int, default=1,
        help="First ID to try (default: 1)"
    )
    parser.add_argument(
        "--end", type=int, default=2_000_000,
        help="Last ID to try (default: 2000000)"
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=50,
        help="Concurrent requests (default: 50)"
    )
    parser.add_argument(
        "-o", "--output", default="results",
        help="Output filename prefix (default: results)"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=10.0,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="Skip second verification request on hits (faster, less accurate)"
    )
    parser.add_argument(
        "--ssl", action="store_true",
        help="Enable SSL certificate verification (off by default for CTF)"
    )
    parser.add_argument(
        "--delay-429", type=float, default=5.0,
        help="Seconds to wait when rate-limited (default: 5)"
    )
    parser.add_argument(
        "--retries", type=int, default=2,
        help="Retry attempts on connection error (default: 2)"
    )
    parser.add_argument(
        "--progress-every", type=int, default=500,
        help="Print progress every N requests (default: 500)"
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.start > args.end:
        print("[!] --start must be less than or equal to --end")
        sys.exit(1)

    total = args.end - args.start + 1
    # Rough ETA assuming ~100 req/s (varies greatly by server + network)
    eta_s = total / max(args.concurrency * 2, 1)

    print("=" * 60)
    print("  Numeric ID Enumerator — CTF Edition")
    print("  Authorized testing only")
    print("=" * 60)
    print(f"  Endpoint    : {args.url}?{args.param}=<id>")
    print(f"  Range       : {args.start:,} → {args.end:,}  ({total:,} IDs)")
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

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        # Windows lands here on Ctrl+C (signal handler not available)
        print("\n\n[!] Ctrl+C — saving partial results…")
        scanner.save_results()
        sys.exit(0)


if __name__ == "__main__":
    main()