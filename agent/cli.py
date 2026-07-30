# `relay` console script. Thin argument-parsing + dispatch only — every
# subcommand below calls the exact same wiring.flows/local_state/
# registry_client functions mcp_server.py and the manual-walkthrough
# scripts already used. No new business logic lives here.
#
# Config replaces hand-typed env vars (RELAY_HANDLE/RELAY_CAPSULE_DIR/
# RELAY_KEY_DIR/RELAY_REGISTRY_URL): `relay init` writes a small TOML
# file once, every other subcommand reads it. RELAY_CONFIG can point at
# an alternate config file — the one deliberate escape hatch, needed to
# run two identities (e.g. @vivek and @friend) from one machine during
# a manual walkthrough, which is otherwise exactly the real one-person-
# one-machine model this whole project assumes.

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path

import httpx

from resolver.rate_limiter import RateLimiter
from wiring.contacts import ContactsStore, resolve_recipient
from wiring.disclosure_log import DisclosureLog
from wiring.flows import (
    PendingResponseRegistry,
    ask,
    check_pending,
    grant,
    resolve_pending_approval,
    revoke,
    run_poll_loop,
    sweep_expired_pending_approvals,
)
from wiring.flows import _my_grants_as_grantor  # existing helper, reused as-is for `relay grants`
from wiring.local_state import LocalIdentity
from wiring.pending_approvals import PendingApprovalStore
from wiring.registry_client import RegistryClient, RegistryRejection
from wiring.threads import ThreadStore

CONFIG_PATH = Path(os.environ.get("RELAY_CONFIG", str(Path.home() / ".relay" / "config.toml")))


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        print(f"no config at {CONFIG_PATH} — run `relay init` first", file=sys.stderr)
        sys.exit(1)
    with open(CONFIG_PATH, "rb") as f:
        return tomllib.load(f)


def _write_config(config: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text("".join(f'{k} = "{v}"\n' for k, v in config.items()))


def _connect(config: dict) -> tuple[LocalIdentity, RegistryClient]:
    identity = LocalIdentity.load_or_create(config["handle"], config["key_dir"])
    registry = RegistryClient.create(config["registry_url"])
    return identity, registry


def _thread_store(config: dict) -> ThreadStore:
    # .get with a fallback: configs written before this feature existed
    # have no "thread_store" key — don't force a `relay init` re-run.
    path = config.get("thread_store", str(CONFIG_PATH.parent / "threads.json"))
    return ThreadStore(path)


def _disclosure_log(config: dict) -> DisclosureLog:
    # Same fallback pattern as _thread_store — configs from before this
    # feature existed have no "disclosure_log" key.
    path = config.get("disclosure_log", str(CONFIG_PATH.parent / "disclosure_log.json"))
    return DisclosureLog(path)


def _pending_approval_store(config: dict) -> PendingApprovalStore:
    # Same fallback pattern as _thread_store/_disclosure_log.
    path = config.get("pending_approvals", str(CONFIG_PATH.parent / "pending_approvals.json"))
    return PendingApprovalStore(path)


def _contacts_store(config: dict) -> ContactsStore:
    # Same fallback pattern as _thread_store/_disclosure_log.
    path = config.get("contacts", str(CONFIG_PATH.parent / "contacts.json"))
    return ContactsStore(path)


def _default_config(handle: str) -> dict:
    base = CONFIG_PATH.parent
    return {
        "handle": handle,
        "capsule_dir": str(base / "capsules"),
        "key_dir": str(base / "keys" / handle),
        "registry_url": f"http://localhost:{DEFAULT_REGISTRY_PORT}",
        "thread_store": str(base / "threads.json"),
        "disclosure_log": str(base / "disclosure_log.json"),
        "pending_approvals": str(base / "pending_approvals.json"),
        "contacts": str(base / "contacts.json"),
    }


REGISTRY_HOME = Path.home() / ".relay"
REGISTRY_PID_FILE = REGISTRY_HOME / "registry.pid"
REGISTRY_LOG_FILE = REGISTRY_HOME / "registry.log"
REPO_ROOT = Path(__file__).resolve().parent.parent  # agent/cli.py -> repo root (contains registry/)
AGENT_DIR = Path(__file__).resolve().parent  # cwd for the detached `relay serve` worker subprocess

# `relay serve` — same detachment approach as serve-registry below
# (start_new_session=True; PPID becomes 1; survives the launching
# terminal closing), reused rather than reinvented (this task's
# explicit instruction).
SERVE_PID_FILE = REGISTRY_HOME / "serve.pid"
SERVE_META_FILE = REGISTRY_HOME / "serve.json"  # {"pid": ..., "started_at": isoformat}
SERVE_LOG_FILE = REGISTRY_HOME / "serve.log"

# macOS-only (this task's explicit scoping decision — no Windows/Linux
# background-service support in this pass, consistent with identity/'s
# existing Unix-first stance).
LAUNCHD_LABEL = "com.relay.serve"
LAUNCHD_PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"

# Non-default ports, deliberately: 8000/5432 are common project defaults —
# on this machine specifically they're already owned by an unrelated
# project's Docker containers (MandateCheck), which was silently answering
# Relay's own health checks with a look-alike 404 the whole time. Relay
# gets its own port for the API and its own dedicated local Postgres
# cluster/port, so the two can never collide regardless of which is
# running.
DEFAULT_REGISTRY_PORT = 8088
RELAY_PG_PORT = 5544
RELAY_PG_DATA_DIR = REGISTRY_HOME / "pgdata"
RELAY_PG_LOG_FILE = REGISTRY_HOME / "pg.log"
DEFAULT_DATABASE_URL = f"postgresql+psycopg://localhost:{RELAY_PG_PORT}/relay_registry"


def _pg_bin(name: str) -> str:
    """Locate a postgresql@16 binary — same installation already used
    throughout this project (`which pg_ctl`/`psql` confirmed it during
    diagnosis), not a new dependency. PATH first, then the Homebrew
    keg-only location (postgresql@16 isn't linked onto PATH by default)."""
    found = shutil.which(name)
    if found:
        return found
    brew_path = Path(f"/opt/homebrew/opt/postgresql@16/bin/{name}")
    if brew_path.exists():
        return str(brew_path)
    return name  # let it fail with a clear "command not found" if truly absent


def _registry_reachable(registry_url: str) -> bool:
    """Not just "something answers" — MandateCheck's unrelated FastAPI
    backend also 404s a made-up route, which is exactly what fooled every
    earlier health check this session. Confirm it's actually Relay via
    the OpenAPI title FastAPI(title="Relay Registry") sets in
    registry/app.py."""
    try:
        response = httpx.get(f"{registry_url.rstrip('/')}/openapi.json", timeout=2.0)
        return response.status_code == 200 and response.json().get("info", {}).get("title") == "Relay Registry"
    except httpx.HTTPError:
        return False


def _pid_alive_from_file(pid_file: Path) -> int | None:
    """PID from a pidfile, but only if that process is actually alive —
    a stale pidfile from a killed/crashed process must not be reported as
    running. Generalized from the registry's own pidfile check so
    `relay serve` (a second, separate detached process) can reuse it
    rather than duplicating this logic."""
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text().strip())
    except ValueError:
        return None
    try:
        os.kill(pid, 0)  # signal 0: existence check only, doesn't actually signal
    except ProcessLookupError:
        return None
    except PermissionError:
        return pid  # exists, just owned by someone else — still "running"
    return pid


def _running_pid() -> int | None:
    return _pid_alive_from_file(REGISTRY_PID_FILE)


UNREACHABLE = "unreachable"


def _registered_pubkey(registry_url: str, handle: str) -> str | None | object:
    """Same check `relay register` relies on (RegistryClient.get_identity
    -> None on 404) — reused here, not duplicated, just called before the
    POST instead of after.

    Returns the registered pubkey hex, None if the handle isn't
    registered, or the UNREACHABLE sentinel if the registry can't be
    reached at all. The sentinel matters because `relay init` is the
    first command anyone runs — often before a registry exists — so a
    down registry must not turn config writing into a hard failure. It
    only means "cannot verify", which is different from "verified as
    mismatched" and must not be conflated with either.
    """
    try:
        registry = RegistryClient.create(registry_url)
        identity_row = registry.get_identity(handle)
    except httpx.HTTPError:
        return UNREACHABLE
    return identity_row["public_key_hex"] if identity_row else None


def cmd_init(args: argparse.Namespace) -> None:
    handle = args.handle or input("Your handle (e.g. vivek): ").strip()
    config = _default_config(handle)
    if args.capsule_dir:
        config["capsule_dir"] = args.capsule_dir
    elif not args.non_interactive:
        answer = input(f"Capsule directory [{config['capsule_dir']}]: ").strip()
        if answer:
            config["capsule_dir"] = answer
    if args.registry_url:
        config["registry_url"] = args.registry_url
    elif not args.non_interactive:
        answer = input(f"Registry URL [{config['registry_url']}]: ").strip()
        if answer:
            config["registry_url"] = answer
    if args.key_dir:
        config["key_dir"] = args.key_dir

    if not args.force:
        registered_pubkey = _registered_pubkey(config["registry_url"], handle)
        if registered_pubkey is UNREACHABLE:
            print(
                f"note: couldn't reach {config['registry_url']} to check whether "
                f"@{handle} is already registered — writing config unverified."
            )
        elif registered_pubkey is not None:
            # Same generate-if-absent path _connect()/LocalIdentity.load_or_create
            # already uses everywhere else — computing the pubkey this
            # key_dir would produce is the only way to compare it.
            local_identity = LocalIdentity.load_or_create(handle, config["key_dir"])
            if local_identity.public_key_hex != registered_pubkey:
                print(f"@{handle} is already registered with a different key.")
                print(f"  registered pubkey:      {registered_pubkey[:12]}...")
                print(f"  this key_dir's pubkey:  {local_identity.public_key_hex[:12]}...")
                print(
                    f"This will point @{handle} at a different keypair than what's "
                    f"registered — you won't be able to sign valid requests until this "
                    f"key is also registered or you point back at the original."
                )
                if args.non_interactive:
                    print("refusing to overwrite non-interactively without --force", file=sys.stderr)
                    sys.exit(1)
                answer = input("Proceed anyway? [y/N]: ").strip().lower()
                if answer not in ("y", "yes"):
                    print("aborted — config not written")
                    sys.exit(1)

    _write_config(config)
    print(f"wrote {CONFIG_PATH}")


def _ensure_relay_postgres(database_url: str) -> None:
    """Own dedicated Postgres cluster on RELAY_PG_PORT, not whatever
    happens to be listening on 5432 (which, on this machine, turned out
    to be an unrelated project's Docker container — see the module-level
    comment by DEFAULT_REGISTRY_PORT). initdb once, pg_ctl start if not
    already up, createdb + apply_schema idempotently. Uses the
    postgresql@16 binaries already installed for this project, not a new
    dependency."""
    if not RELAY_PG_DATA_DIR.exists():
        print(f"initializing dedicated Postgres cluster at {RELAY_PG_DATA_DIR} (one-time)...")
        subprocess.run(
            [_pg_bin("initdb"), "-D", str(RELAY_PG_DATA_DIR), "-U", os.environ.get("USER", "postgres"), "-A", "trust"],
            check=True, capture_output=True, text=True,
        )

    pg_isready = subprocess.run(
        [_pg_bin("pg_isready"), "-h", "127.0.0.1", "-p", str(RELAY_PG_PORT)], capture_output=True, text=True,
    )
    if pg_isready.returncode != 0:
        print(f"starting dedicated Postgres on port {RELAY_PG_PORT}...")
        subprocess.run(
            [
                _pg_bin("pg_ctl"), "-D", str(RELAY_PG_DATA_DIR), "-l", str(RELAY_PG_LOG_FILE),
                "-o", f"-p {RELAY_PG_PORT} -h 127.0.0.1", "start",
            ],
            check=True, capture_output=True, text=True,
        )
        for _ in range(20):
            if subprocess.run(
                [_pg_bin("pg_isready"), "-h", "127.0.0.1", "-p", str(RELAY_PG_PORT)], capture_output=True
            ).returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError(f"Postgres didn't come up on port {RELAY_PG_PORT} — check {RELAY_PG_LOG_FILE}")

    createdb = subprocess.run(
        [_pg_bin("createdb"), "-h", "127.0.0.1", "-p", str(RELAY_PG_PORT), "relay_registry"],
        capture_output=True, text=True,
    )
    if createdb.returncode != 0 and "already exists" not in createdb.stderr:
        raise RuntimeError(f"createdb failed: {createdb.stderr}")

    # registry/ is a sibling top-level package, not importable from
    # agent/'s own path — run its migrate module the same way
    # cmd_serve_registry runs uvicorn (subprocess, cwd=REPO_ROOT, its own
    # DATABASE_URL), rather than hacking sys.path in-process.
    migrate_env = dict(os.environ)
    migrate_env["DATABASE_URL"] = database_url
    migrate = subprocess.run(
        [sys.executable, "-m", "registry.db.migrate"],
        cwd=REPO_ROOT, env=migrate_env, capture_output=True, text=True,
    )
    if migrate.returncode != 0:
        raise RuntimeError(f"schema migration failed: {migrate.stderr}")


def cmd_serve_registry(args: argparse.Namespace) -> None:
    registry_url = f"http://localhost:{args.port}"
    if _registry_reachable(registry_url):
        print(f"registry already running and reachable at {registry_url}")
        return

    pid = _running_pid()
    if pid is not None:
        print(
            f"registry.pid says pid {pid} is running, but {registry_url} isn't answering "
            f"— it may still be starting, bound to a different port, or wedged. "
            f"Check {REGISTRY_LOG_FILE}."
        )
        return

    REGISTRY_HOME.mkdir(parents=True, exist_ok=True)
    database_url = args.database_url or DEFAULT_DATABASE_URL
    _ensure_relay_postgres(database_url)

    env = dict(os.environ)
    env["DATABASE_URL"] = database_url

    with open(REGISTRY_LOG_FILE, "a") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "registry.app:app", "--port", str(args.port)],
            cwd=REPO_ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,  # detaches from this shell's process group —
            # the actual fix: a plain `uvicorn ... &` stays in the launching
            # shell's session and dies on that shell's SIGHUP when it closes.
            # start_new_session=True (setsid) means closing this terminal
            # does not touch the child.
        )
    REGISTRY_PID_FILE.write_text(str(process.pid))

    # Give it a moment, then confirm — don't just claim success.
    for _ in range(10):
        if _registry_reachable(registry_url):
            print(f"started registry, pid {process.pid}, reachable at {registry_url}")
            print(f"logs: {REGISTRY_LOG_FILE}")
            return
        time.sleep(0.5)
    print(
        f"started process (pid {process.pid}) but {registry_url} isn't answering yet "
        f"— check {REGISTRY_LOG_FILE} (common cause: DATABASE_URL's database doesn't "
        f"exist yet — see README's `createdb`/`registry.db.migrate` setup step)."
    )


def cmd_registry_status(args: argparse.Namespace) -> None:
    registry_url = f"http://localhost:{args.port}"
    reachable = _registry_reachable(registry_url)
    pid = _running_pid()
    print(f"registry_url: {registry_url}")
    print(f"reachable:    {reachable}")
    print(f"pid:          {pid if pid is not None else '(no pidfile / not running)'}")
    if not reachable:
        print(f"not answering — run `relay serve-registry` (logs at {REGISTRY_LOG_FILE})")


def cmd_whoami(args: argparse.Namespace) -> None:
    config = _load_config()
    identity, registry = _connect(config)
    registered_pubkey = _registered_pubkey(config["registry_url"], config["handle"])

    print(f"handle:  {config['handle']}")
    print(f"key_dir: {config['key_dir']}")
    if registered_pubkey is UNREACHABLE:
        print(f"status:  unknown — couldn't reach {config['registry_url']}")
    elif registered_pubkey is None:
        print("status:  not yet registered")
    elif registered_pubkey == identity.public_key_hex:
        print(f"status:  registered, key matches (pubkey {identity.public_key_hex[:12]}...)")
    else:
        print(
            f"status:  MISMATCH — registered pubkey {registered_pubkey[:12]}... "
            f"but this key_dir's pubkey is {identity.public_key_hex[:12]}... "
            f"(signed requests will fail invalid_signature)"
        )

    if registered_pubkey not in (UNREACHABLE, None):
        # Own relay number — give this out like a phone number so others
        # can `relay contacts add <name> <relay-number>` (this task's
        # Part 1 item 7).
        own_identity = registry.get_identity(config["handle"])
        if own_identity is not None:
            print(f"relay_number: {own_identity['relay_number']}")


def cmd_register(args: argparse.Namespace) -> None:
    if not CONFIG_PATH.exists():
        if not args.handle:
            print(f"no config at {CONFIG_PATH} and no handle given — run `relay register <handle>` or `relay init`", file=sys.stderr)
            sys.exit(1)
        _write_config(_default_config(args.handle))
        print(f"wrote {CONFIG_PATH}")

    config = _load_config()
    identity, registry = _connect(config)
    try:
        result = registry.register_identity(identity.handle, identity.public_key_hex, identity.encryption_public_key_hex)
        print(f"registered @{identity.handle} (pubkey {identity.public_key_hex[:12]}...)")
        print(f"your relay number: {result['relay_number']} — give this out instead of your handle, like a phone number")
    except RegistryRejection as e:
        # Checked by status_code, not e.outcome: identity_routes.py's
        # duplicate-handle rejection returns a plain-string `detail`
        # (FastAPI's default HTTPException shape), not the structured
        # {"outcome": ..., "message": ...} body grant/relay endpoints
        # use — so RegistryClient._raise_for_rejection can't populate
        # e.outcome as "duplicate_handle" here; e.status_code is read
        # before that parsing and is unaffected by the body's shape.
        if e.status_code == 409:
            print(f"@{identity.handle} already registered")
        else:
            raise


def _wrap_preserving_paragraphs(text: str) -> str:
    """Wrap to terminal width without collapsing existing line breaks —
    capsule content and manual answers may already contain real
    paragraph/line structure that must survive, and no content is ever
    cut off (textwrap.fill never truncates, only re-flows)."""
    width = max(shutil.get_terminal_size(fallback=(88, 24)).columns, 20)
    return "\n".join(textwrap.fill(line, width=width) if line.strip() else "" for line in text.split("\n"))


def _format_result(result: dict, *, recipient: str | None = None) -> str:
    """cmd_ask/cmd_check's own terminal presentation of ask()/check_pending()'s
    return dict — the dict itself (what MCP/tests consume) is untouched;
    this only decides how a human reads it. Handles any question/answer
    shape (long, short, multi-paragraph, no-capsule manual answers) the
    same way: don't assume a fixed length or a capsule source always
    being present."""
    if result.get("status") == "pending":
        return result.get("message", "not answered yet")

    outcome = result.get("outcome")
    answer = (result.get("answer") or "").strip()
    cited = result.get("cited_capsule_ids") or []
    who = f" by @{recipient}" if recipient else ""

    if outcome in ("approved_whole", "approved_excerpt"):
        header = f"✓ Answered{who}"
    elif outcome == "manual_answer":
        header = f"✓ Answered{who} (typed directly, no document shared)"
    elif outcome == "denied":
        header = "✗ Not shared"
    else:
        header = f"({outcome or 'unknown outcome'})"

    lines = [header, "", _wrap_preserving_paragraphs(answer) if answer else "(no answer text)"]
    if cited:
        lines += ["", f"Source: {', '.join(cited)}"]
    thread_id = result.get("thread_id")
    if thread_id:
        lines += ["", f"Thread: {thread_id} — reply with: relay ask <recipient> '...' --thread {thread_id}"]
    return "\n".join(lines)


def _resolve_reason_and_urgency(args: argparse.Namespace) -> tuple[str, str]:
    """CLI-only interactive fallback — the wiring.flows.ask() function
    itself just takes reason/urgency as plain strings with "" defaults;
    this is where "prompt interactively unless provided as flags" (this
    task's explicit CLI requirement) actually happens."""
    reason = args.reason
    if reason is None:
        reason = input("Why do you need this? (one line, optional): ").strip()
    urgent = args.urgent
    if urgent is None:
        answer = input("Is this time-sensitive? [y/N or a short reason]: ").strip()
        if not answer or answer.lower() in ("n", "no"):
            urgent = ""
        elif answer.lower() in ("y", "yes"):
            urgent = "urgent"
        else:
            urgent = f"urgent: {answer}"
    return reason, urgent


def cmd_ask(args: argparse.Namespace) -> None:
    config = _load_config()
    identity, registry = _connect(config)
    rate_limiter = RateLimiter()
    response_registry = PendingResponseRegistry()
    thread_store = _thread_store(config)
    disclosure_log = _disclosure_log(config)
    reason, urgency = _resolve_reason_and_urgency(args)
    # Additive: a saved contact name resolves to its relay number, then
    # to the real handle via the registry; a raw handle (existing usage)
    # passes through unchanged (this task's explicit non-breaking rule).
    recipient = resolve_recipient(_contacts_store(config), registry, args.recipient)

    poll_thread = threading.Thread(
        target=run_poll_loop,
        args=(
            identity, registry, config["capsule_dir"], rate_limiter, response_registry, thread_store,
            disclosure_log,
        ),
        kwargs={"interval_secs": 2.0},
        daemon=True,
    )
    poll_thread.start()

    print(f'asking @{recipient}: "{args.question}"')
    result = ask(
        identity, registry, recipient, args.question, response_registry, thread_store,
        thread_id=args.thread, reason=reason, urgency=urgency,
        wait_attempts=args.wait_attempts, wait_interval=args.wait_interval,
    )
    print(_format_result(result, recipient=recipient))


def cmd_check(args: argparse.Namespace) -> None:
    config = _load_config()
    identity, registry = _connect(config)
    rate_limiter = RateLimiter()
    response_registry = PendingResponseRegistry()
    thread_store = _thread_store(config)
    disclosure_log = _disclosure_log(config)
    result = check_pending(
        identity, registry, config["capsule_dir"], rate_limiter, response_registry, thread_store, disclosure_log,
        args.request_id,
    )
    print(_format_result(result))


def cmd_listen(args: argparse.Namespace) -> None:
    config = _load_config()
    identity, registry = _connect(config)
    rate_limiter = RateLimiter()
    response_registry = PendingResponseRegistry()  # unused on the listening side; run_poll_loop requires it
    thread_store = _thread_store(config)
    disclosure_log = _disclosure_log(config)
    # --headless: the actual worker `relay serve` spawns as a detached
    # subprocess (see cmd_serve below) — passing a PendingApprovalStore
    # is what makes process_incoming_ask queue ad hoc requests instead
    # of blocking on terminal input() that no one is there to answer.
    # Interactive `relay listen` never sets this (pending_approval_store
    # stays None), so its behavior is completely unchanged.
    pending_approval_store = _pending_approval_store(config) if args.headless else None
    if args.headless:
        print(f"listening headless as @{identity.handle} every {args.interval}s — approval requests will be "
              f"queued and notified, not prompted here; run `relay pending` to answer them.")
    else:
        print(f"listening as @{identity.handle} every {args.interval}s (Ctrl+C to stop)...")
    run_poll_loop(
        identity, registry, config["capsule_dir"], rate_limiter, response_registry, thread_store, disclosure_log,
        pending_approval_store=pending_approval_store, interval_secs=args.interval,
    )


def _launchd_plist_xml(relay_bin: str, interval: float) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{relay_bin}</string>
        <string>listen</string>
        <string>--headless</string>
        <string>--interval</string>
        <string>{interval}</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>{SERVE_LOG_FILE}</string>
    <key>StandardErrorPath</key><string>{SERVE_LOG_FILE}</string>
</dict>
</plist>
"""


def _relay_bin() -> str:
    """The installed `relay` console script's absolute path — launchd
    does not source shell rc files/PATH the way an interactive shell
    does, so the plist must point at an absolute path. Falls back to
    the venv-standard sibling-of-python location if `which` can't find
    it (e.g. this shell's venv isn't currently activated)."""
    found = shutil.which("relay")
    if found:
        return found
    return str(Path(sys.executable).parent / "relay")


def cmd_serve(args: argparse.Namespace) -> None:
    if args.install_autostart:
        REGISTRY_HOME.mkdir(parents=True, exist_ok=True)
        LAUNCHD_PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        LAUNCHD_PLIST_PATH.write_text(_launchd_plist_xml(_relay_bin(), args.interval))
        subprocess.run(["launchctl", "unload", str(LAUNCHD_PLIST_PATH)], capture_output=True)  # ok if not loaded
        result = subprocess.run(["launchctl", "load", "-w", str(LAUNCHD_PLIST_PATH)], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"installed autostart: {LAUNCHD_PLIST_PATH}")
            print("`relay serve` (headless) will now start automatically on login")
        else:
            print(f"wrote {LAUNCHD_PLIST_PATH} but `launchctl load` failed: {result.stderr.strip()}")
        return

    if args.uninstall_autostart:
        if not LAUNCHD_PLIST_PATH.exists():
            print("autostart was not installed")
            return
        subprocess.run(["launchctl", "unload", str(LAUNCHD_PLIST_PATH)], capture_output=True)
        LAUNCHD_PLIST_PATH.unlink()
        print(f"removed autostart: {LAUNCHD_PLIST_PATH}")
        return

    pid = _pid_alive_from_file(SERVE_PID_FILE)
    if pid is not None:
        print(f"relay serve already running, pid {pid} — run `relay serve-status` for details")
        return

    REGISTRY_HOME.mkdir(parents=True, exist_ok=True)
    with open(SERVE_LOG_FILE, "a") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "cli", "listen", "--headless", "--interval", str(args.interval)],
            cwd=AGENT_DIR,
            env=dict(os.environ),
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,  # same detachment as serve-registry above: PPID becomes 1,
            # survives this terminal closing — reused exactly, not reinvented.
        )
    SERVE_PID_FILE.write_text(str(process.pid))
    SERVE_META_FILE.write_text(json.dumps({"pid": process.pid, "started_at": datetime.now(timezone.utc).isoformat()}))

    time.sleep(0.5)  # give it a moment, then confirm — don't just claim success
    if _pid_alive_from_file(SERVE_PID_FILE) is not None:
        print(f"started relay serve, pid {process.pid}")
        print(f"logs: {SERVE_LOG_FILE}")
        print("ad hoc approval requests will show a native notification — run `relay pending` to answer them")
    else:
        print(f"started process (pid {process.pid}) but it exited immediately — check {SERVE_LOG_FILE}")


def cmd_serve_status(args: argparse.Namespace) -> None:
    pid = _pid_alive_from_file(SERVE_PID_FILE)
    print(f"pid: {pid if pid is not None else '(no pidfile / not running)'}")
    if pid is None:
        print(f"not running — run `relay serve` (logs at {SERVE_LOG_FILE})")
        return
    if SERVE_META_FILE.exists():
        try:
            meta = json.loads(SERVE_META_FILE.read_text())
            started_at = datetime.fromisoformat(meta["started_at"])
            print(f"started_at: {meta['started_at']}")
            print(f"uptime:     {datetime.now(timezone.utc) - started_at}")
        except (ValueError, KeyError, OSError):
            pass  # meta file missing/corrupt is not a reason to fail the whole status check
    print(f"logs:       {SERVE_LOG_FILE}")
    print(f"autostart:  {'installed' if LAUNCHD_PLIST_PATH.exists() else 'not installed'} ({LAUNCHD_PLIST_PATH})")


def cmd_serve_stop(args: argparse.Namespace) -> None:
    pid = _pid_alive_from_file(SERVE_PID_FILE)
    if pid is None:
        print("relay serve is not running")
        SERVE_PID_FILE.unlink(missing_ok=True)
        SERVE_META_FILE.unlink(missing_ok=True)
        return
    os.kill(pid, signal.SIGTERM)
    for _ in range(20):
        if _pid_alive_from_file(SERVE_PID_FILE) is None:
            break
        time.sleep(0.25)
    else:
        print(f"sent SIGTERM to pid {pid} but it's still alive after 5s — check {SERVE_LOG_FILE}")
        return
    SERVE_PID_FILE.unlink(missing_ok=True)
    SERVE_META_FILE.unlink(missing_ok=True)
    print(f"stopped relay serve (was pid {pid})")


def cmd_pending(args: argparse.Namespace) -> None:
    config = _load_config()
    identity, registry = _connect(config)
    thread_store = _thread_store(config)
    disclosure_log = _disclosure_log(config)
    pending_store = _pending_approval_store(config)

    # Same auto-deny-on-expiry sweep `relay serve`'s poll loop already
    # runs every tick — run it here too so `relay pending` never shows
    # (or lets someone answer) a request that's already past its own
    # expiry_duration (CLAUDE.md §2: unanswered must always resolve to
    # auto-deny, never a silent grant, and never a stale live prompt).
    swept = sweep_expired_pending_approvals(identity, registry, thread_store, pending_store)
    if swept:
        print(f"{swept} request(s) had already expired and were auto-denied")

    items = pending_store.list()
    if not items:
        print("no pending approval requests")
        return

    print(f"{len(items)} pending approval request(s) — answering one at a time:")
    for item in items:
        print(f"\n--- from @{item.sender} ---")
        resolve_pending_approval(identity, registry, config["capsule_dir"], thread_store, disclosure_log, item)
        pending_store.pop(item.nonce)


def cmd_contacts_add(args: argparse.Namespace) -> None:
    config = _load_config()
    _contacts_store(config).add(args.name, args.relay_number)
    print(f"saved contact {args.name!r} -> {args.relay_number}")


def cmd_contacts_list(args: argparse.Namespace) -> None:
    config = _load_config()
    contacts = _contacts_store(config).list()
    if not contacts:
        print("no saved contacts")
        return
    for contact in contacts:
        # Masked display (this task's explicit requirement) — never the
        # handle (contacts.py never even stores it locally), and the
        # relay number itself is shortened so a shared screen doesn't
        # trivially expose the full routing id.
        masked = f"{contact.relay_number[:4]}…"
        print(f"{contact.name}\t{masked}")


def cmd_contacts_remove(args: argparse.Namespace) -> None:
    config = _load_config()
    if _contacts_store(config).remove(args.name):
        print(f"removed contact {args.name!r}")
    else:
        print(f"no contact named {args.name!r}")


def cmd_thread(args: argparse.Namespace) -> None:
    config = _load_config()
    thread_store = _thread_store(config)
    record = thread_store.get(args.thread_id)
    if record is None:
        print(f"no thread {args.thread_id!r} found locally")
        return
    print(f"Thread {record.thread_id}: @{record.sender} -> @{record.recipient}")
    print(f"created:        {record.created_at}")
    print(f"last activity:  {record.last_activity_at}")
    print(f"approved so far: {sorted(record.approved_capsule_ids) or '(none)'}")
    print()
    for i, message in enumerate(record.messages, start=1):
        print(f"[{i}] ({message.outcome or 'pending'}) {message.at}")
        print(f"  Q: {message.question}")
        print(f"  A: {message.answer or '(no answer yet)'}")
        print()


def cmd_grant(args: argparse.Namespace) -> None:
    config = _load_config()
    identity, registry = _connect(config)
    capsule_ids = [s.strip() for s in args.scope.split(",") if s.strip()]
    grantee = resolve_recipient(_contacts_store(config), registry, args.grantee)
    grant_id = grant(identity, registry, grantee, "standing", capsule_ids)
    print(f"created grant {grant_id} ({grantee} <- {capsule_ids})")


def cmd_grants(args: argparse.Namespace) -> None:
    """List grants THIS identity created for a grantee — existing
    registry.list_grants + flows._my_grants_as_grantor filtering, just
    surfaced so a human has a grant_id to pass to `relay revoke`."""
    config = _load_config()
    identity, registry = _connect(config)
    grantee = resolve_recipient(_contacts_store(config), registry, args.grantee)
    for g in _my_grants_as_grantor(registry, identity, grantee):
        print(f"{g.type.value}\tcapsules={sorted(g.capsule_ids)}\trevoked={g.revoked}\texpires_at={g.expires_at}")


def cmd_revoke(args: argparse.Namespace) -> None:
    config = _load_config()
    identity, registry = _connect(config)
    revoke(identity, registry, args.grant_id)
    print(f"revoked {args.grant_id}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="relay")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="write local config (handle, capsule dir, registry URL)")
    p_init.add_argument("--handle")
    p_init.add_argument("--capsule-dir", dest="capsule_dir")
    p_init.add_argument("--registry-url", dest="registry_url")
    p_init.add_argument("--key-dir", dest="key_dir")
    p_init.add_argument("--non-interactive", action="store_true")
    p_init.add_argument("--force", action="store_true", help="skip the already-registered-with-a-different-key confirmation")
    p_init.set_defaults(func=cmd_init)

    p_whoami = sub.add_parser("whoami", help="show current config and whether the local key matches what's registered")
    p_whoami.set_defaults(func=cmd_whoami)

    p_serve = sub.add_parser("serve-registry", help="start the local registry, detached, surviving this terminal closing")
    p_serve.add_argument("--port", type=int, default=DEFAULT_REGISTRY_PORT)
    p_serve.add_argument("--database-url", dest="database_url", default=None)
    p_serve.set_defaults(func=cmd_serve_registry)

    p_regstatus = sub.add_parser("registry-status", help="check whether the local registry is up and reachable")
    p_regstatus.add_argument("--port", type=int, default=DEFAULT_REGISTRY_PORT)
    p_regstatus.set_defaults(func=cmd_registry_status)

    p_register = sub.add_parser("register", help="register this identity's public keys with the registry")
    p_register.add_argument("handle", nargs="?", help="only needed the first time, if no config exists yet")
    p_register.set_defaults(func=cmd_register)

    p_ask = sub.add_parser("ask", help="ask another handle a question")
    p_ask.add_argument("recipient")
    p_ask.add_argument("question")
    p_ask.add_argument("--thread", default=None, help="continue an existing conversation by its thread id")
    p_ask.add_argument("--reason", default=None, help="why you need this (one line); prompted interactively if omitted")
    p_ask.add_argument(
        "--urgent", nargs="?", const="urgent", default=None,
        help="mark time-sensitive, optionally with a short reason; prompted interactively if omitted",
    )
    p_ask.add_argument("--wait-attempts", type=int, default=60)
    p_ask.add_argument("--wait-interval", type=float, default=5.0)
    p_ask.set_defaults(func=cmd_ask)

    p_check = sub.add_parser("check", help="check whether a pending ask has been answered yet")
    p_check.add_argument("request_id")
    p_check.set_defaults(func=cmd_check)

    p_listen = sub.add_parser("listen", help="poll for incoming asks and handle live approval prompts")
    p_listen.add_argument("--interval", type=float, default=2.0)
    p_listen.add_argument(
        "--headless", action="store_true",
        help="queue ad hoc approvals + notify instead of blocking on terminal input (used by `relay serve`)",
    )
    p_listen.set_defaults(func=cmd_listen)

    p_serve = sub.add_parser(
        "serve", help="run `relay listen --headless` as a detached background process, surviving this terminal closing",
    )
    p_serve.add_argument("--interval", type=float, default=2.0)
    p_serve.add_argument(
        "--install-autostart", action="store_true",
        help="install a launchd agent (macOS only) so `relay serve` restarts automatically on login",
    )
    p_serve.add_argument("--uninstall-autostart", action="store_true", help="remove the launchd autostart agent")
    p_serve.set_defaults(func=cmd_serve)

    p_serve_status = sub.add_parser("serve-status", help="check whether `relay serve` is running, pid, uptime")
    p_serve_status.set_defaults(func=cmd_serve_status)

    p_serve_stop = sub.add_parser("serve-stop", help="stop the running `relay serve` background process")
    p_serve_stop.set_defaults(func=cmd_serve_stop)

    p_pending = sub.add_parser(
        "pending", help="answer approval requests queued while `relay serve` was running headless",
    )
    p_pending.set_defaults(func=cmd_pending)

    p_thread = sub.add_parser("thread", help="show the full local history of a conversation thread")
    p_thread.add_argument("thread_id")
    p_thread.set_defaults(func=cmd_thread)

    p_contacts = sub.add_parser("contacts", help="manage local contacts (name -> relay number)")
    contacts_sub = p_contacts.add_subparsers(dest="contacts_command", required=True)

    p_contacts_add = contacts_sub.add_parser("add", help="save a contact")
    p_contacts_add.add_argument("name")
    p_contacts_add.add_argument("relay_number")
    p_contacts_add.set_defaults(func=cmd_contacts_add)

    p_contacts_list = contacts_sub.add_parser("list", help="list saved contacts")
    p_contacts_list.set_defaults(func=cmd_contacts_list)

    p_contacts_remove = contacts_sub.add_parser("remove", help="remove a saved contact")
    p_contacts_remove.add_argument("name")
    p_contacts_remove.set_defaults(func=cmd_contacts_remove)

    p_grant = sub.add_parser("grant", help="create a standing grant for a set of capsule IDs")
    p_grant.add_argument("grantee")
    p_grant.add_argument("--scope", required=True, help="comma-separated capsule IDs")
    p_grant.set_defaults(func=cmd_grant)

    p_grants = sub.add_parser("grants", help="list grants you created for a grantee (to find a grant_id to revoke)")
    p_grants.add_argument("grantee")
    p_grants.set_defaults(func=cmd_grants)

    p_revoke = sub.add_parser("revoke", help="revoke a standing grant by its grant_id (see `relay grants`)")
    p_revoke.add_argument("grant_id")
    p_revoke.set_defaults(func=cmd_revoke)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
