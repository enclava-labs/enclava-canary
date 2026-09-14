#!/usr/bin/env python3
"""enclava-canary — minimal healthy workload for custom-image deploy tests,
extended with the bounded capacity payload used by the S1792 shape tests.

Serves a polished page that surfaces the in-pod attestation-proxy's verified
claims (SEV-SNP attestation info + ownership status), proving the app really
runs inside a confidential VM.

Capacity payload contract (see worker1-tenant-capacity-reliability plan E1):

- All initialization — bounded workload allocation, encrypted-volume marker
  creation/verification — completes BEFORE the HTTP listener opens, so
  `/health` can only ever return its exact `ok` body once persistent-state
  access and workload setup have genuinely succeeded. An init failure exits
  the process instead of serving a degraded health response.
- `GET /work` is the single bounded work endpoint. It uses only fixed
  synthetic input (touching the in-process allocation and hashing the state
  marker); no request parameter can select commands, paths, sizes, or
  destinations.
- The workload holds a bounded in-process allocation calibrated once at
  startup so the TOTAL app-container working set (Python + request handling
  included) lands near 96 MiB — it is never resized per request.
- One marker file lives on the declared encrypted app-data volume, with a
  small breadcrumb file beside it. Both are created exactly once on a fresh
  volume (durable write/fsync/rename + directory fsync) and thereafter only
  read. The marker is self-validating: it embeds the SHA-256 of its payload,
  so any corruption fails init or the check — the marker is never
  regenerated mid-check to force a pass. A marker that vanishes while its
  breadcrumb survives also fails init rather than being silently recreated;
  only a volume with neither file is treated as new.
- The old visit counter remains a UI/continuity feature only; the marker is
  the integrity oracle for this controlled persistence scenario.
- `/work` returns the marker's SHA-256 (computed by reading the file each
  request, never a cached checksum) plus a fixed-schema numeric telemetry
  object: timestamp, app current/peak memory, cgroup memory limit, and
  workload-ready state. No filesystem browsing, logs, secrets, attestation
  reports, or hardware identifiers.
- `CANARY_NOISY=1` enables a short bounded noisy-output mode used only for
  the signed-runtime output-path check; it is off by default and never runs
  during capacity measurement.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import socket
import sys
import tempfile
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
INDEX = HERE / "index.html"

# ---------------------------------------------------------------------------
# Configuration. Everything is env-bound at process start and validated before
# the listener opens; invalid config exits nonzero instead of serving.
# ---------------------------------------------------------------------------

MIB = 1024 * 1024
PAGE = 4096

# Total target working set for the app container, in MiB. The bounded
# allocation is sized as (target - measured baseline - headroom) so the whole
# app — interpreter, buffers, request handling — lands inside the 88-104 MiB
# acceptance band. The headroom reserve covers per-request growth.
DEFAULT_TARGET_RSS_MIB = 96
MIN_TARGET_RSS_MIB = 48
MAX_TARGET_RSS_MIB = 256
REQUEST_HEADROOM_MIB = 8

# Marker layout v2 (self-validating):
#   MAGIC || random payload || sha256(MAGIC || payload)
# The embedded digest makes any corruption of the stored payload detectable
# on read — a damaged marker fails init /work instead of passing with a
# different checksum.
MARKER_MAGIC = b"ENCLAVA-CANARY-MARKER\x00v2\x00"
MARKER_RANDOM_BYTES = 32
MARKER_DIGEST_BYTES = 32
MARKER_LEN = len(MARKER_MAGIC) + MARKER_RANDOM_BYTES + MARKER_DIGEST_BYTES

# Companion file written next to the marker with the same durable discipline.
# Its presence means "this volume once held a marker": if the marker later
# vanishes while the breadcrumb survives, init fails instead of silently
# recreating state. Residual: a fully wiped volume (both gone) is
# indistinguishable from a new one and gets a fresh marker — that IS a
# fresh volume.
BREADCRUMB_BYTES = b"ENCLAVA-CANARY-BREADCRUMB\x00v1\x00"

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

NOISY_BYTES_PER_STREAM = 512 * 1024  # > pipe capacity; exercises backpressure.
NOISY_LINE_BYTES = 2048


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip()


def _parse_port() -> int:
    raw = _env("PORT", "8080")
    try:
        port = int(raw, 10)
    except (TypeError, ValueError):
        raise SystemExit(f"invalid PORT {raw!r}: not an integer")
    if not 1 <= port <= 65535:
        raise SystemExit(f"invalid PORT {raw!r}: out of range 1-65535")
    return port


def _parse_flag(name: str) -> bool:
    raw = _env(name, "0")
    if raw in ("0", "false", "no"):
        return False
    if raw in ("1", "true", "yes"):
        return True
    raise SystemExit(f"invalid {name} {raw!r}: expected 0/1/true/false")


def _parse_target_rss_mib() -> int:
    raw = _env("CANARY_TARGET_RSS_MIB", str(DEFAULT_TARGET_RSS_MIB))
    try:
        mib = int(raw, 10)
    except (TypeError, ValueError):
        raise SystemExit(f"invalid CANARY_TARGET_RSS_MIB {raw!r}: not an integer")
    if not MIN_TARGET_RSS_MIB <= mib <= MAX_TARGET_RSS_MIB:
        raise SystemExit(
            f"invalid CANARY_TARGET_RSS_MIB {raw!r}: "
            f"out of range {MIN_TARGET_RSS_MIB}-{MAX_TARGET_RSS_MIB}"
        )
    return mib


PORT = _parse_port()
PROXY = _env("ATTESTATION_PROXY", "http://127.0.0.1:8081")
NOISY = _parse_flag("CANARY_NOISY")
TARGET_RSS_MIB = _parse_target_rss_mib()

# The declared encrypted app-data volume is bind-mounted into the workload at
# its storage.paths entry (/app/data for this image; VOLUME-declared because
# the rootfs is read-only). CANARY_DATA_DIR only exists so local checks can
# point the payload at a scratch directory — it is not request-controllable.
DATA_DIR = Path(_env("CANARY_DATA_DIR", "/app/data"))
VISITS = Path(_env("VISITS_FILE", str(DATA_DIR / "visits")))
MARKER = DATA_DIR / "marker.bin"
BREADCRUMB = DATA_DIR / ".marker.breadcrumb"

# Numeric boot summary written once by enclava-init onto the shared
# /run/enclava emptyDir before it marks readiness. Read fresh per request;
# absent (older init images) is reported as null, never fabricated.
INIT_STATS_PATH = Path(_env("CANARY_INIT_STATS", "/run/enclava/init-stats.json"))

WORKLOAD_READY = False
ALLOCATION: bytearray | None = None


def fetch(path: str, timeout: float = 2.0):
    """GET <proxy><path> as JSON. Never raises — returns {"_error": ...} so the
    page degrades gracefully (e.g. /status 404s in auto-unlock mode)."""
    try:
        with urllib.request.urlopen(f"{PROXY}{path}", timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:  # ponytail: one net for all failures; demo only.
        return {"_error": f"{type(e).__name__}: {e}"}


def bump_visits() -> int | None:
    """Tiny visit counter proving the storage.paths bind is writable by the
    workload. UI/continuity only — the marker file is the integrity oracle.
    None when the mount is absent/unwritable — the page then shows "no mount",
    which is honest, not a crash."""
    try:
        VISITS.parent.mkdir(parents=True, exist_ok=True)
        n = (int(VISITS.read_text().strip()) + 1) if VISITS.exists() else 1
        VISITS.write_text(str(n))
        return n
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Capacity payload: bounded allocation + durable marker on app-data volume.
# ---------------------------------------------------------------------------


def _rss_kib() -> int | None:
    try:
        status = Path("/proc/self/status").read_text()
    except OSError:
        return None
    match = re.search(r"^VmRSS:\s+(\d+) kB", status, re.M)
    return int(match.group(1)) if match else None


def _hwm_kib() -> int | None:
    try:
        status = Path("/proc/self/status").read_text()
    except OSError:
        return None
    match = re.search(r"^VmHWM:\s+(\d+) kB", status, re.M)
    return int(match.group(1)) if match else None


def _memory_limit_bytes() -> int:
    """Cgroup memory limit for this container, or 0 when unlimited/unknown.

    Tries cgroup v2 then v1. A fixed-schema numeric field: 0 means "no finite
    limit observed", not an error.
    """
    try:
        raw = Path("/sys/fs/cgroup/memory.max").read_text().strip()
        if raw != "max":
            return int(raw)
    except (OSError, ValueError):
        pass
    try:
        raw = Path(
            "/sys/fs/cgroup/memory/memory.limit_in_bytes"
        ).read_text().strip()
        value = int(raw)
        # v1 reports ~PiB-scale sentinel values for "unlimited".
        if 0 < value < (1 << 60):
            return value
    except (OSError, ValueError):
        pass
    return 0


def _setup_workload() -> None:
    """Allocate the bounded working set once and touch every page.

    Sizes the allocation off the measured post-init baseline so the TOTAL app
    working set approaches TARGET_RSS_MIB rather than adding the target on top
    of whatever Python already holds. Never resized afterwards.
    """
    global ALLOCATION, WORKLOAD_READY
    baseline_kib = _rss_kib()
    if baseline_kib is None:
        raise SystemExit("cannot measure baseline RSS; refusing to size workload")
    budget_kib = TARGET_RSS_MIB * 1024 - baseline_kib - REQUEST_HEADROOM_MIB * 1024
    if budget_kib <= 0:
        raise SystemExit(
            f"baseline RSS {baseline_kib} KiB leaves no room for workload "
            f"under target {TARGET_RSS_MIB} MiB"
        )
    ALLOCATION = bytearray(budget_kib * 1024)
    _touch_allocation()
    WORKLOAD_READY = True


def _touch_allocation() -> None:
    """Fixed synthetic work: write one byte per page across the whole bounded
    allocation so the pages stay resident. Runs identically on every call —
    no request input can change the amount or the target."""
    buf = ALLOCATION
    if buf is None:
        return
    marker = int(time.time()) & 0xFF
    for off in range(0, len(buf), PAGE):
        buf[off] = marker


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    """Write every byte or raise. os.write may legally return a short count;
    a truncated marker must never be fsynced and renamed into place."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("os.write made no progress")
        view = view[written:]


def _durable_write(path: Path, data: bytes, tmp_prefix: str) -> None:
    """Write `data` to `path` durably: unique sibling temp file, full write,
    fsync, length verify, atomic rename, directory fsync.

    The temp name comes from mkstemp so a stale leftover from a crashed
    earlier init — including one created by the same PID (PID 1 in a
    container) — can never collide with O_EXCL. The temp name is always
    cleaned up on failure."""
    fd, tmp_name = tempfile.mkstemp(prefix=tmp_prefix, dir=DATA_DIR)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        _write_all(fd, data)
        os.fsync(fd)
        if os.fstat(fd).st_size != len(data):
            raise OSError(
                f"durable write of {path.name} incomplete: "
                f"{os.fstat(fd).st_size} != {len(data)} bytes"
            )
        os.close(fd)
        fd = -1
        os.rename(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass  # already renamed, or removal failed — nothing to do
    _fsync_dir(DATA_DIR)


def _clear_stale_tmp() -> None:
    """Remove leftover marker/breadcrumb temp files from a crashed earlier
    init. unlink() removes only the directory entry — a planted symlink or
    hardlink target is never touched. Entries that cannot be removed (e.g.
    a directory squatting on the prefix) are ignored: mkstemp's unique
    suffixes mean they cannot wedge creation."""
    for pattern in (".marker.tmp.*", ".breadcrumb.tmp.*"):
        try:
            stale = list(DATA_DIR.glob(pattern))
        except OSError:
            continue  # unreadable dir — the probe/marker ops will fail anyway
        for entry in stale:
            try:
                entry.unlink()
            except OSError:
                pass


def _marker_bytes_ok(data: bytes) -> bool:
    """Full structural + integrity check of the v2 marker layout."""
    if len(data) != MARKER_LEN or not data.startswith(MARKER_MAGIC):
        return False
    body, digest = data[:-MARKER_DIGEST_BYTES], data[-MARKER_DIGEST_BYTES:]
    return hashlib.sha256(body).digest() == digest


def _read_marker() -> bytes:
    """Read the marker from the volume. Raises on any failure — callers turn
    that into init failure or a failed check, never a silent recreate.

    Reads at most MARKER_LEN + 1 bytes so an oversized corrupt file cannot
    exhaust the bounded container memory, and refuses symlinks so the marker
    name itself must be the real file."""
    fd = os.open(MARKER, os.O_RDONLY | _O_NOFOLLOW)
    try:
        chunks = []
        remaining = MARKER_LEN + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if not _marker_bytes_ok(data):
        raise ValueError(
            f"marker corrupt: {len(data)} bytes, bad magic, or digest mismatch"
        )
    return data


def _probe_writable() -> None:
    """Prove the app-data mount is writable with a durable probe write. A
    read-only or absent mount must fail init even when the marker already
    exists, so a broken volume cannot pass as a healthy one.

    O_EXCL|O_NOFOLLOW: the probe never truncates or follows an existing
    `.writetest` name — a symlink planted at that path cannot redirect the
    probe onto the marker. A leftover name is unlinked (name-level removal
    never touches a link target) and retried once; anything still in the way
    fails init, which is the safe direction."""
    probe = DATA_DIR / ".writetest"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW
    try:
        fd = os.open(probe, flags, 0o600)
    except FileExistsError:
        os.unlink(probe)
        fd = os.open(probe, flags, 0o600)
    try:
        _write_all(fd, b"w")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.unlink(probe)
    _fsync_dir(DATA_DIR)


def _setup_marker() -> None:
    """Create the marker once on a fresh volume; verify it on an existing one.

    Creation is durable: unique sibling temp file, full write + fsync, atomic
    rename, directory fsync — for both the marker and its breadcrumb. An
    existing marker is only read and validated; a corrupt marker fails init
    rather than being replaced. A breadcrumb without a marker means the
    marker vanished from a volume that had one — init fails instead of
    recreating state. Both absent means a genuinely fresh (or fully wiped)
    volume: create both."""
    if not DATA_DIR.is_dir():
        raise SystemExit(f"app-data mount {DATA_DIR} missing or not a directory")
    _clear_stale_tmp()
    if MARKER.exists():
        _read_marker()  # raises -> init fails on corrupt marker
        _probe_writable()
        if not os.path.lexists(BREADCRUMB):
            # Crash between marker rename and breadcrumb write on the very
            # first init: the marker itself is intact, so record the
            # breadcrumb now with the same durable discipline.
            _durable_write(BREADCRUMB, BREADCRUMB_BYTES, ".breadcrumb.tmp.")
        return
    if os.path.lexists(BREADCRUMB):
        raise SystemExit(
            f"app-data marker vanished from {DATA_DIR} (breadcrumb present): "
            "refusing to recreate persistent state"
        )
    _probe_writable()
    body = MARKER_MAGIC + os.urandom(MARKER_RANDOM_BYTES)
    payload = body + hashlib.sha256(body).digest()
    _durable_write(MARKER, payload, ".marker.tmp.")
    _durable_write(BREADCRUMB, BREADCRUMB_BYTES, ".breadcrumb.tmp.")


def marker_sha256() -> str:
    """SHA-256 of the marker, computed from a fresh read every request."""
    return hashlib.sha256(_read_marker()).hexdigest()


def _numeric_tree(value) -> bool:
    if isinstance(value, bool):
        return False  # JSON bool is not a number for this contract.
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        # NaN/Infinity are accepted by json.loads but are not standard JSON
        # and would re-serialize as nonstandard literals — reject them.
        return math.isfinite(value)
    if isinstance(value, dict):
        return all(_numeric_tree(v) for v in value.values())
    return False


def init_stats() -> dict | None:
    """enclava-init's numeric-only boot summary, or None when the image does
    not provide one. Passed through only when every leaf is a finite number
    so the endpoint stays a fixed numeric record rather than a file proxy.
    Decode failures (bad UTF-8, bad JSON) are reported as absent, never as
    an uncaught handler error."""
    try:
        data = json.loads(INIT_STATS_PATH.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not _numeric_tree(data):
        return None
    return data


def telemetry() -> dict:
    """Fixed-schema numeric telemetry for the capacity harness. All values are
    numbers; the schema never grows request-selected or identifying fields."""
    rss = _rss_kib()
    hwm = _hwm_kib()
    return {
        "ts": int(time.time()),
        "mem_current_bytes": (rss * 1024) if rss is not None else 0,
        "mem_peak_bytes": (hwm * 1024) if hwm is not None else 0,
        "mem_limit_bytes": _memory_limit_bytes(),
        "workload_ready": 1 if WORKLOAD_READY else 0,
    }


def noisy_burst() -> None:
    """Bounded noisy-output mode for the signed-runtime output-path check.

    Emits a fixed >64KiB burst on each of stdout/stderr once at startup and a
    short line per /work request. Off unless CANARY_NOISY=1; the byte counts
    are compile-time constants, never request/env sized at runtime."""
    chunk = (b"canary-noise " * (NOISY_BYTES_PER_STREAM // 13 + 1))[
        :NOISY_BYTES_PER_STREAM
    ]
    for stream in (sys.stdout, sys.stderr):
        stream.buffer.write(chunk)
        stream.buffer.flush()


def noisy_tick() -> None:
    if not NOISY:
        return
    line = (b"work " * (NOISY_LINE_BYTES // 5 + 1))[:NOISY_LINE_BYTES]
    for stream in (sys.stdout, sys.stderr):
        stream.buffer.write(line + b"\n")
        stream.buffer.flush()


class H(BaseHTTPRequestHandler):
    server_version = "enclava-canary"

    def do_GET(self):
        if self.path == "/health":
            # Init precedes listen, so reaching this handler already means
            # workload setup + marker verification succeeded; the flag is a
            # second belt on the same contract.
            if WORKLOAD_READY:
                self._send(200, b"ok", "text/plain")
            else:  # pragma: no cover - unreachable once serving
                self._send(503, b"not ready", "text/plain")
        elif self.path == "/work":
            self._work()
        elif self.path == "/":
            payload = {
                "attestation_info": fetch("/v1/attestation/info"),
                "ownership_status": fetch("/status"),
                "guest": {"hostname": socket.gethostname(), "visits": bump_visits()},
            }
            page = INDEX.read_text().replace("__ATTESTATION_JSON__", json.dumps(payload))
            self._send(200, page.encode(), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def _work(self) -> None:
        noisy_tick()
        _touch_allocation()
        try:
            checksum = marker_sha256()
        except (OSError, ValueError) as e:
            # Missing/corrupt marker is a check failure — never regenerated.
            self._send(
                503,
                json.dumps({"error": "marker_invalid", "detail": str(e)}).encode(),
                "application/json",
            )
            return
        body = json.dumps(
            {
                "marker_sha256": checksum,
                "telemetry": telemetry(),
                "init_stats": init_stats(),
            },
            sort_keys=True,
        ).encode()
        self._send(200, body, "application/json")

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # ponytail: enclava relays logs encrypted; keep stderr quiet.
        pass


def main() -> None:
    _setup_workload()
    _setup_marker()
    if NOISY:
        noisy_burst()
    print(
        f"enclava-canary listening on 0.0.0.0:{PORT} "
        f"(proxy={PROXY}, data={DATA_DIR}, "
        f"alloc={len(ALLOCATION) // MIB}MiB, target={TARGET_RSS_MIB}MiB)",
        flush=True,
    )
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()


if __name__ == "__main__":
    main()
