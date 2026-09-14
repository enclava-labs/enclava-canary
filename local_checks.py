#!/usr/bin/env python3
"""Local checks for the enclava-canary capacity payload (plan Stage E1).

Stdlib only — no live cluster, no attestation proxy, no credentials. Each
check launches `server.py` as a subprocess against a scratch data dir that
stands in for the encrypted app-data mount.

  1. /health returns the exact body "ok" once init succeeds.
  2. The marker's SHA-256 survives a full process restart and /work re-reads
     the file (checksum equals hashing the on-disk bytes).
  3. Missing app-data dir, read-only app-data dir, and a corrupt pre-existing
     marker each fail init — the process exits nonzero and never serves.
  4. The bounded workload reports total RSS inside the 88-104 MiB acceptance
     band and stays under the 128 MiB container limit across /work traffic.
  5. Invalid config (bad PORT, bad CANARY_NOISY, out-of-range target) exits
     nonzero without serving.

Regression checks for the codex-review findings:

  6. A marker that vanishes while its breadcrumb survives fails init instead
     of being silently recreated; a fully wiped volume is treated as fresh.
  7. The writable probe never follows a planted `.writetest` symlink or
     truncates an existing file; a stale probe name is reclaimed safely.
  8. Stale `.marker.tmp.*`/`.breadcrumb.tmp.*` files from a crashed init are
     cleaned and cannot collide with the new unique temp names.
  9. os.write short-counts are looped; a stalled writer aborts creation and
     never renames a truncated marker into place.
 10. Corruption inside the marker payload (not just length/magic) fails init
     and /work — the marker is self-validating via an embedded digest.
 11. Marker reads are capped at MARKER_LEN+1 bytes; an oversized file fails
     fast instead of being read whole into the bounded container.
 12. init_stats: invalid UTF-8, NaN, and nonfinite floats are suppressed to
     null rather than crashing the handler or emitting nonstandard JSON.

Usage: python3 local_checks.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"
MIB = 1024 * 1024

FAILURES: list[str] = []

# Import the payload module for unit-level checks. Clear any CANARY_*/PORT
# env so the module's import-time config parse always sees defaults; the
# filesystem paths it binds are monkeypatched per check.
for _v in (
    "PORT",
    "CANARY_NOISY",
    "CANARY_TARGET_RSS_MIB",
    "CANARY_DATA_DIR",
    "CANARY_INIT_STATS",
    "VISITS_FILE",
    "ATTESTATION_PROXY",
):
    os.environ.pop(_v, None)
sys.path.insert(0, str(HERE))
import server as srv  # noqa: E402


def _point_server_at(data: Path) -> None:
    """Redirect the imported payload's module-level paths at a scratch dir."""
    srv.DATA_DIR = data
    srv.VISITS = data / "visits"
    srv.MARKER = data / "marker.bin"
    srv.BREADCRUMB = data / ".marker.breadcrumb"


def check(name: str, cond: bool, detail: str = "") -> None:
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        FAILURES.append(name)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _spawn(data_dir: Path, extra_env: dict | None = None) -> tuple[subprocess.Popen, int]:
    port = _free_port()
    env = dict(os.environ)
    env.update(
        {
            "PORT": str(port),
            "CANARY_DATA_DIR": str(data_dir),
            "PYTHONUNBUFFERED": "1",
        }
    )
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen(
        [sys.executable, str(SERVER)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc, port


def _wait_ready(proc: subprocess.Popen, port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health", timeout=1
            ) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.1)
    return False


def _get(port: int, path: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}{path}", timeout=5
        ) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _expect_exit(env_extra: dict, timeout: float = 10.0) -> tuple[int, float]:
    """Spawn with bogus env; expect a fast nonzero exit and no listener."""
    port = _free_port()
    env = dict(os.environ)
    env.update({"PORT": str(port), "PYTHONUNBUFFERED": "1"})
    env.update(env_extra)
    proc = subprocess.Popen(
        [sys.executable, str(SERVER)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return -1, -1.0
    # Nothing may be listening afterwards.
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/health", timeout=1
        ) as r:
            if r.status == 200:
                return 0, -1.0
    except Exception:
        pass
    return rc, port


def check_health_exact(scratch: Path) -> None:
    data = scratch / "health-data"
    data.mkdir()
    proc, port = _spawn(data)
    try:
        check("health: server becomes ready", _wait_ready(proc, port))
        code, body = _get(port, "/health")
        check(
            "health: exact 'ok' body",
            code == 200 and body == b"ok",
            f"code={code} body={body!r}",
        )
        check(
            "health: marker created durably on fresh volume",
            (data / "marker.bin").is_file(),
        )
        check(
            "health: breadcrumb recorded next to marker",
            (data / ".marker.breadcrumb").is_file(),
        )
    finally:
        _stop(proc)


def check_marker_restart(scratch: Path) -> None:
    data = scratch / "restart-data"
    data.mkdir()

    proc, port = _spawn(data)
    try:
        assert _wait_ready(proc, port)
        code, body = _get(port, "/work")
        first = json.loads(body)
        code1 = code
    finally:
        _stop(proc)
    check("restart: first /work 200 with checksum", code1 == 200)

    on_disk = (data / "marker.bin").read_bytes()
    check(
        "restart: /work checksum equals fresh on-disk hash",
        first["marker_sha256"] == hashlib.sha256(on_disk).hexdigest(),
    )

    proc, port = _spawn(data)
    try:
        check("restart: second boot becomes ready", _wait_ready(proc, port))
        code, body = _get(port, "/work")
        second = json.loads(body)
        check(
            "restart: marker checksum identical across restart",
            code == 200 and second["marker_sha256"] == first["marker_sha256"],
        )
        check(
            "restart: marker bytes untouched",
            (data / "marker.bin").read_bytes() == on_disk,
        )
    finally:
        _stop(proc)


def check_storage_failures(scratch: Path) -> None:
    missing = scratch / "does-not-exist"
    rc, _ = _expect_exit({"CANARY_DATA_DIR": str(missing)})
    check("storage: missing app-data dir fails init", rc not in (0, -1), f"rc={rc}")

    corrupt = scratch / "corrupt-data"
    corrupt.mkdir()
    (corrupt / "marker.bin").write_bytes(b"not a real marker")
    rc, _ = _expect_exit({"CANARY_DATA_DIR": str(corrupt)})
    check("storage: corrupt marker fails init, no regen", rc not in (0, -1), f"rc={rc}")
    check(
        "storage: corrupt marker left in place",
        (corrupt / "marker.bin").read_bytes() == b"not a real marker",
    )

    # Marker deleted mid-run -> /work fails, marker is NOT regenerated.
    data = scratch / "midrun-data"
    data.mkdir()
    proc, port = _spawn(data)
    try:
        assert _wait_ready(proc, port)
        (data / "marker.bin").unlink()
        code, body = _get(port, "/work")
        check(
            "storage: deleted marker fails /work with 503",
            code == 503,
            f"code={code} body={body!r}",
        )
        check(
            "storage: marker not regenerated mid-check",
            not (data / "marker.bin").exists(),
        )
        code, _ = _get(port, "/health")
        check("storage: health still ok after marker loss (init-time gate)", code == 200)
    finally:
        _stop(proc)


def check_readonly_storage(scratch: Path) -> None:
    """A read-only app-data mount must fail init. Mode bits alone do not bind
    root (the image's default user), so when the harness runs as root the
    payload is spawned under an unprivileged uid against a non-writable dir;
    the server.py copy lives in world-traversable scratch because the repo
    path may not be. If privilege drop is unavailable the limitation is
    reported explicitly — the unit-level EACCES probe check in
    check_probe_safety still covers the probe's code path."""
    ro = scratch / "ro-data"
    ro.mkdir()

    if os.geteuid() != 0:
        # Non-root: owner r-x without w genuinely denies the probe create.
        ro.chmod(stat.S_IRUSR | stat.S_IXUSR)  # 0500
        try:
            rc, _ = _expect_exit({"CANARY_DATA_DIR": str(ro)})
            check(
                "storage: read-only app-data dir fails init",
                rc not in (0, -1),
                f"rc={rc} euid={os.geteuid()} (mode 0500 binds non-root)",
            )
        finally:
            ro.chmod(0o700)
        return

    # Root: drop to an unprivileged uid in the child so filesystem permission
    # checks apply. Dir stays root-owned 0555 — traversable, not writable.
    ro.chmod(0o555)
    srv_copy = scratch / "server-as-nobody.py"
    shutil.copy(SERVER, srv_copy)
    srv_copy.chmod(0o644)
    scratch.chmod(0o711)  # let the dropped uid traverse to the copy + data dir

    def _drop_privs() -> None:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)

    setpriv = shutil.which("setpriv")
    if setpriv:
        cmd = [
            setpriv,
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            sys.executable,
            str(srv_copy),
        ]
        preexec = None
    else:
        cmd = [sys.executable, str(srv_copy)]
        preexec = _drop_privs

    port = _free_port()
    env = dict(os.environ)
    env.update(
        {
            "PORT": str(port),
            "CANARY_DATA_DIR": str(ro),
            "PYTHONUNBUFFERED": "1",
        }
    )
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=preexec,
        )
    except Exception as e:
        check(
            "storage: read-only app-data dir fails init",
            False,
            f"cannot drop privileges to simulate ({e}); unit-level EACCES "
            "probe check still covers the code path",
        )
        return
    try:
        rc = proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        rc = -1
    check(
        "storage: read-only app-data dir fails init",
        rc not in (0, -1),
        f"rc={rc} (spawned as uid 65534, dir mode 0555)",
    )


def check_marker_vanish(scratch: Path) -> None:
    """Finding 1: a marker that disappears between restarts fails init — the
    surviving breadcrumb proves the volume once held one, so absence is not
    'fresh volume'. Only both files gone means genuinely fresh/wiped."""
    data = scratch / "vanish-data"
    data.mkdir()
    proc, port = _spawn(data)
    try:
        assert _wait_ready(proc, port)
    finally:
        _stop(proc)

    (data / "marker.bin").unlink()
    rc, _ = _expect_exit({"CANARY_DATA_DIR": str(data)})
    check(
        "vanish: missing marker + surviving breadcrumb fails init",
        rc not in (0, -1),
        f"rc={rc}",
    )
    check(
        "vanish: marker not recreated on the failed restart",
        not (data / "marker.bin").exists(),
    )
    check(
        "vanish: breadcrumb left in place (evidence, not deleted)",
        (data / ".marker.breadcrumb").is_file(),
    )

    # Documented residual: a fully wiped volume is indistinguishable from a
    # new one — with neither file present init succeeds and creates both.
    (data / ".marker.breadcrumb").unlink()
    proc, port = _spawn(data)
    try:
        check(
            "vanish: fully wiped volume treated as fresh",
            _wait_ready(proc, port),
        )
        check(
            "vanish: fresh marker + breadcrumb recreated",
            (data / "marker.bin").is_file()
            and (data / ".marker.breadcrumb").is_file(),
        )
    finally:
        _stop(proc)


def check_probe_safety(scratch: Path) -> None:
    """Finding 2: the writable probe must never follow a planted `.writetest`
    symlink into the marker or truncate an existing file. Unit-level via the
    imported module — the syscall behavior is what matters, not the HTTP
    layer."""
    data = scratch / "probe-data"
    data.mkdir()
    _point_server_at(data)
    srv._setup_marker()
    marker_bytes = srv.MARKER.read_bytes()
    probe = data / ".writetest"

    # Crash-between-marker-and-breadcrumb: intact marker, no breadcrumb —
    # init must succeed and backfill the breadcrumb durably.
    srv.BREADCRUMB.unlink()
    srv._setup_marker()
    check(
        "probe: missing breadcrumb backfilled when marker is intact",
        srv.BREADCRUMB.is_file()
        and srv.MARKER.read_bytes() == marker_bytes,
    )

    # Planted symlink .writetest -> marker.bin: the probe must not truncate
    # or otherwise touch the marker through it.
    probe.symlink_to("marker.bin")
    threw = False
    try:
        srv._probe_writable()
    except OSError:
        threw = True
    check(
        "probe: .writetest symlink cannot destroy the marker",
        srv.MARKER.read_bytes() == marker_bytes,
    )
    check(
        "probe: planted name unlinked (name-level only) and probe proceeds",
        not threw and not os.path.lexists(probe),
    )

    # Stale regular file at the probe name: reclaimed, never truncated in
    # place (O_EXCL create after unlink).
    probe.write_bytes(b"stale")
    srv._probe_writable()
    check(
        "probe: stale regular .writetest reclaimed",
        not os.path.lexists(probe) and srv.MARKER.read_bytes() == marker_bytes,
    )

    # A directory squatting on the name cannot be unlinked -> fails safe.
    probe.mkdir()
    try:
        srv._probe_writable()
        threw = False
    except OSError:
        threw = True
    finally:
        probe.rmdir()
    check("probe: .writetest directory fails safe", threw)

    # Read-only mount code path, simulated at the syscall layer so it binds
    # regardless of the harness uid (root included).
    real_open = os.open

    def _deny_probe(path, flags, mode=0o777, *, dir_fd=None):
        if str(path).endswith(".writetest"):
            raise PermissionError(13, "simulated read-only mount")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    os.open = _deny_probe
    try:
        try:
            srv._probe_writable()
            threw = False
        except PermissionError:
            threw = True
    finally:
        os.open = real_open
    check("probe: EACCES on probe create propagates as init failure", threw)


def check_stale_tmp(scratch: Path) -> None:
    """Finding 3: leftover temp files from a crashed init (including the old
    PID-derived naming, e.g. `.marker.tmp.1` under a PID-1 container) are
    removed and cannot collide — mkstemp gives every attempt a unique name."""
    data = scratch / "tmp-data"
    data.mkdir()
    for name in (".marker.tmp.1", ".marker.tmp.999999", ".breadcrumb.tmp.1"):
        (data / name).write_bytes(b"partial")
    proc, port = _spawn(data)
    try:
        check(
            "stale-tmp: init succeeds with crash leftovers present",
            _wait_ready(proc, port),
        )
        leftovers = sorted(p.name for p in data.iterdir() if ".tmp." in p.name)
        check(
            "stale-tmp: crash leftovers cleaned",
            leftovers == [],
            f"left={leftovers}",
        )
        check(
            "stale-tmp: marker + breadcrumb created",
            (data / "marker.bin").is_file()
            and (data / ".marker.breadcrumb").is_file(),
        )
    finally:
        _stop(proc)


def check_write_integrity(scratch: Path) -> None:
    """Finding 4: os.write may legally return a short count. The durable
    write must loop until complete and must never rename a truncated file
    into place."""
    real_write = os.write

    # (a) Short writes still produce a complete, valid marker.
    data = scratch / "write-data"
    data.mkdir()
    _point_server_at(data)

    def _short_write(fd, buf):
        return real_write(fd, buf[:7])

    os.write = _short_write
    try:
        srv._setup_marker()
    finally:
        os.write = real_write
    marker_bytes = srv.MARKER.read_bytes()
    check(
        "write: short os.write calls still yield a valid full marker",
        len(marker_bytes) == srv.MARKER_LEN and srv._marker_bytes_ok(marker_bytes),
        f"len={len(marker_bytes)} expected={srv.MARKER_LEN}",
    )

    # (b) A writer that stalls mid-payload aborts creation: no marker, no
    # tmp debris.
    data2 = scratch / "write-data2"
    data2.mkdir()
    _point_server_at(data2)
    calls = {"n": 0}

    def _stalling_write(fd, buf):
        calls["n"] += 1
        if calls["n"] > 3:
            return 0  # device stops accepting data mid-payload
        return real_write(fd, buf[:5])

    os.write = _stalling_write
    threw = None
    try:
        srv._setup_marker()
    except OSError as e:
        threw = e
    finally:
        os.write = real_write
    check(
        "write: stalled os.write aborts marker creation",
        isinstance(threw, OSError),
        f"threw={threw!r}",
    )
    check(
        "write: no truncated marker renamed into place",
        not (data2 / "marker.bin").exists(),
    )
    debris = [p.name for p in data2.iterdir() if ".tmp." in p.name]
    check("write: no tmp debris left behind", debris == [], f"debris={debris}")


def check_payload_corruption(scratch: Path) -> None:
    """Finding 5: the marker is self-validating — corruption inside the
    random payload (length and magic intact) must fail /work and init, not
    pass with a different checksum."""
    data = scratch / "corrupt-payload"
    data.mkdir()
    proc, port = _spawn(data)
    try:
        assert _wait_ready(proc, port)
        code, body = _get(port, "/work")
        check(
            "corrupt: baseline /work 200 with checksum",
            code == 200 and "marker_sha256" in json.loads(body),
            f"code={code}",
        )
        marker_path = data / "marker.bin"
        raw = bytearray(marker_path.read_bytes())
        raw[len(srv.MARKER_MAGIC) + 4] ^= 0xFF  # inside the payload region
        marker_path.write_bytes(bytes(raw))
        code, body = _get(port, "/work")
        check(
            "corrupt: flipped payload byte fails /work with 503",
            code == 503,
            f"code={code} body={body!r}",
        )
    finally:
        _stop(proc)

    rc, _ = _expect_exit({"CANARY_DATA_DIR": str(data)})
    check(
        "corrupt: payload-corrupt marker fails init",
        rc not in (0, -1),
        f"rc={rc}",
    )

    # Corrupting the embedded digest instead is equally detected.
    data2 = scratch / "corrupt-digest"
    data2.mkdir()
    proc, port = _spawn(data2)
    try:
        assert _wait_ready(proc, port)
    finally:
        _stop(proc)
    marker_path2 = data2 / "marker.bin"
    raw2 = bytearray(marker_path2.read_bytes())
    raw2[-1] ^= 0xFF  # stored digest no longer matches the payload
    marker_path2.write_bytes(bytes(raw2))
    rc, _ = _expect_exit({"CANARY_DATA_DIR": str(data2)})
    check(
        "corrupt: digest-corrupt marker fails init",
        rc not in (0, -1),
        f"rc={rc}",
    )


def check_bounded_read(scratch: Path) -> None:
    """Finding 6: marker reads are capped at MARKER_LEN+1 bytes so an
    oversized corrupt file cannot exhaust the bounded container memory."""
    data = scratch / "oversize-data"
    data.mkdir()
    _point_server_at(data)
    srv._setup_marker()
    marker_path = data / "marker.bin"
    with marker_path.open("ab") as f:
        f.write(b"X" * (4 * MIB))  # valid prefix, wrong total length

    seen = {"n": 0}
    real_read = os.read

    def _spy_read(fd, n):
        chunk = real_read(fd, n)
        seen["n"] += len(chunk)
        return chunk

    os.read = _spy_read
    threw = None
    try:
        srv._read_marker()
    except ValueError as e:
        threw = e
    finally:
        os.read = real_read
    check("bounded-read: oversized marker rejected", isinstance(threw, ValueError))
    check(
        "bounded-read: at most MARKER_LEN+1 bytes consumed",
        seen["n"] <= srv.MARKER_LEN + 1,
        f"read={seen['n']} cap={srv.MARKER_LEN + 1}",
    )

    # End-to-end: the same oversized file fails init rather than serving.
    rc, _ = _expect_exit({"CANARY_DATA_DIR": str(data)})
    check(
        "bounded-read: oversized marker fails init",
        rc not in (0, -1),
        f"rc={rc}",
    )


def check_workload_band(scratch: Path) -> None:
    data = scratch / "band-data"
    data.mkdir()
    proc, port = _spawn(data)
    try:
        check("band: server becomes ready", _wait_ready(proc, port))
        last = None
        for _ in range(10):
            code, body = _get(port, "/work")
            check_ok = code == 200
            if not check_ok:
                check("band: /work 200", False, f"code={code} body={body!r}")
                return
            last = json.loads(body)
        tele = last["telemetry"]
        cur = tele["mem_current_bytes"]
        peak = tele["mem_peak_bytes"]
        check(
            "band: total RSS in 88-104 MiB acceptance band",
            88 * MIB <= cur <= 104 * MIB,
            f"current={cur / MIB:.1f} MiB",
        )
        check(
            "band: peak under 128 MiB container limit",
            peak < 128 * MIB,
            f"peak={peak / MIB:.1f} MiB",
        )
        check("band: workload_ready == 1", tele["workload_ready"] == 1)
        check(
            "band: telemetry schema numeric and fixed",
            set(tele)
            == {"ts", "mem_current_bytes", "mem_peak_bytes", "mem_limit_bytes", "workload_ready"}
            and all(isinstance(v, (int, float)) for v in tele.values()),
            f"schema={sorted(tele)}",
        )
        # Marker checksum + telemetry + init stats only: no extra keys.
        check(
            "band: /work response is marker + telemetry + init_stats only",
            set(last) == {"marker_sha256", "telemetry", "init_stats"},
            f"keys={sorted(last)}",
        )
        check(
            "band: init_stats null when no init record exists",
            last["init_stats"] is None,
        )
    finally:
        _stop(proc)


def check_init_stats_passthrough(scratch: Path) -> None:
    data = scratch / "stats-data"
    data.mkdir()
    stats_file = scratch / "init-stats.json"
    stats_file.write_text(
        json.dumps(
            {
                "version": 1,
                "init_start_unix": 1700000000,
                "durations_ms": {"state_volume": 120, "tls_volume": 30},
                "volume_formatted": {"state": 1, "tls": 1},
                "guest_mem_total_bytes": 1024 * MIB,
                "guest_mem_available_bytes": {"init_start": 9, "post_luks": 8, "ready": 7},
                "init_cgroup_peak_bytes": 42 * MIB,
            }
        )
    )
    proc, port = _spawn(data, {"CANARY_INIT_STATS": str(stats_file)})
    try:
        check("init_stats: server becomes ready", _wait_ready(proc, port))
        code, body = _get(port, "/work")
        payload = json.loads(body)
        check(
            "init_stats: numeric record passed through verbatim",
            code == 200 and payload["init_stats"]["durations_ms"]["state_volume"] == 120,
        )
        # A record carrying non-numeric leaves must be suppressed, not leaked.
        stats_file.write_text(json.dumps({"version": 1, "note": "see logs"}))
        code, body = _get(port, "/work")
        payload = json.loads(body)
        check(
            "init_stats: non-numeric record suppressed",
            code == 200 and payload["init_stats"] is None,
        )
        stats_file.write_text("not json")
        code, body = _get(port, "/work")
        payload = json.loads(body)
        check(
            "init_stats: corrupt record suppressed",
            code == 200 and payload["init_stats"] is None,
        )
        # Finding 7: invalid UTF-8 must suppress to null, not raise
        # UnicodeDecodeError and abort the handler mid-response.
        stats_file.write_bytes(b'{"version": 1, "raw": "\xff\xfe\xfd"}')
        code, body = _get(port, "/work")
        payload = json.loads(body)
        check(
            "init_stats: invalid UTF-8 suppressed to null",
            code == 200 and payload["init_stats"] is None,
            f"code={code}",
        )
        # Nonfinite numerics (accepted by json.loads, not standard JSON) are
        # rejected at every nesting level.
        for label, doc in [
            ("NaN literal", '{"version": 1, "x": NaN}'),
            ("Infinity literal", '{"version": 1, "x": Infinity}'),
            ("overflow float 1e999", '{"version": 1, "x": 1e999}'),
            ("nested -Infinity", '{"version": 1, "n": {"x": -Infinity}}'),
        ]:
            stats_file.write_text(doc)
            code, body = _get(port, "/work")
            payload = json.loads(body)
            check(
                f"init_stats: nonfinite suppressed ({label})",
                code == 200 and payload["init_stats"] is None,
                f"code={code}",
            )
        # Positive control: finite floats still pass through.
        stats_file.write_text('{"version": 1, "x": 1.5, "y": -2}')
        code, body = _get(port, "/work")
        payload = json.loads(body)
        check(
            "init_stats: finite floats pass through",
            code == 200
            and payload["init_stats"] == {"version": 1, "x": 1.5, "y": -2},
        )
    finally:
        _stop(proc)


def check_invalid_config(scratch: Path) -> None:
    data = scratch / "cfg-data"
    data.mkdir()
    for label, env_extra in [
        ("PORT not an integer", {"PORT": "abc"}),
        ("PORT out of range", {"PORT": "70000"}),
        ("CANARY_NOISY not a flag", {"CANARY_NOISY": "banana"}),
        (
            "CANARY_TARGET_RSS_MIB out of range",
            {"CANARY_TARGET_RSS_MIB": "100000"},
        ),
        (
            "CANARY_TARGET_RSS_MIB negative",
            {"CANARY_TARGET_RSS_MIB": "-5"},
        ),
    ]:
        env_full = dict(env_extra)
        env_full.setdefault("CANARY_DATA_DIR", str(data))
        rc, _ = _expect_exit(env_full)
        check(f"config: {label} rejected", rc not in (0, -1), f"rc={rc}")


def check_noisy_mode(scratch: Path) -> None:
    data = scratch / "noisy-data"
    data.mkdir()
    port = _free_port()
    env = dict(os.environ)
    env.update(
        {
            "PORT": str(port),
            "CANARY_DATA_DIR": str(data),
            "CANARY_NOISY": "1",
            "PYTHONUNBUFFERED": "1",
        }
    )
    proc = subprocess.Popen(
        [sys.executable, str(SERVER)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # The burst intentionally exceeds pipe capacity; drain both streams
    # concurrently so the check measures payload behavior, not the harness
    # deadlocking on its own undrained pipes.
    captured: dict[str, bytes] = {}

    def _drain(name: str, stream) -> None:
        captured[name] = stream.read()

    threads = [
        threading.Thread(target=_drain, args=("out", proc.stdout), daemon=True),
        threading.Thread(target=_drain, args=("err", proc.stderr), daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        check("noisy: noisy-mode server becomes ready", _wait_ready(proc, port))
        code, _ = _get(port, "/work")
        check("noisy: /work still 200", code == 200)
    finally:
        _stop(proc)
    for t in threads:
        t.join(timeout=5)
    out, err = captured.get("out", b""), captured.get("err", b"")
    check(
        "noisy: bounded burst on both streams (>64KiB each)",
        len(out) > 64 * 1024 and len(err) > 64 * 1024,
        f"stdout={len(out)} stderr={len(err)}",
    )
    check(
        "noisy: burst is bounded (<4MiB each)",
        len(out) < 4 * MIB and len(err) < 4 * MIB,
    )


def main() -> int:
    scratch = Path(tempfile.mkdtemp(prefix="canary-checks-"))
    try:
        check_health_exact(scratch)
        check_marker_restart(scratch)
        check_storage_failures(scratch)
        check_readonly_storage(scratch)
        check_marker_vanish(scratch)
        check_probe_safety(scratch)
        check_stale_tmp(scratch)
        check_write_integrity(scratch)
        check_payload_corruption(scratch)
        check_bounded_read(scratch)
        check_workload_band(scratch)
        check_init_stats_passthrough(scratch)
        check_invalid_config(scratch)
        check_noisy_mode(scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    if FAILURES:
        print(f"\n{len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("\nAll local checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
