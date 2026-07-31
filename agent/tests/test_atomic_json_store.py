# Concurrency test for atomic_json_store.py's locked()/atomic_write_json
# — proves the actual risk this fix closes: REAL separate OS processes
# (not just threads in one process) writing to the SAME store file at
# the same time must not lose each other's updates. Uses
# multiprocessing (spawn) rather than threading specifically because
# the real-world scenario is `relay serve`'s background process vs. a
# concurrent manual CLI invocation — two different processes, not two
# threads in one.
#
# Top-level worker functions (not closures) — required for
# multiprocessing's spawn start method (macOS default) to pickle them.

from __future__ import annotations

import multiprocessing as mp

from wiring.contacts import ContactsStore
from wiring.threads import ThreadStore


def _worker_add_contacts(path: str, worker_id: int, count: int) -> None:
    store = ContactsStore(path)
    for i in range(count):
        store.add(f"contact-{worker_id}-{i}", f"{worker_id:02d}{i:06d}")


def test_concurrent_processes_adding_contacts_lose_nothing(tmp_path):
    path = str(tmp_path / "contacts.json")
    n_workers, n_per_worker = 6, 25

    procs = [
        mp.Process(target=_worker_add_contacts, args=(path, worker_id, n_per_worker))
        for worker_id in range(n_workers)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)
        assert p.exitcode == 0

    final = ContactsStore(path).list()
    assert len(final) == n_workers * n_per_worker  # every single add survived — none clobbered
    names = {c.name for c in final}
    expected = {f"contact-{w}-{i}" for w in range(n_workers) for i in range(n_per_worker)}
    assert names == expected


def _worker_record_messages(path: str, thread_id: str, worker_id: int, count: int) -> None:
    from datetime import datetime, timezone

    store = ThreadStore(path)
    for i in range(count):
        store.record_message(
            thread_id, question=f"q-{worker_id}-{i}", answer="", outcome="pending",
            now=datetime.now(timezone.utc), nonce=f"{worker_id}-{i}",
        )


def test_concurrent_processes_appending_thread_messages_lose_nothing(tmp_path):
    path = str(tmp_path / "threads.json")
    thread_id = "shared-thread"
    n_workers, n_per_worker = 6, 25

    # Seed the thread record first (get_or_create), same as a real
    # first ask() would, before any concurrent writers touch it.
    from datetime import datetime, timezone

    ThreadStore(path).get_or_create(thread_id, sender="vivek", recipient="rohan", now=datetime.now(timezone.utc))

    procs = [
        mp.Process(target=_worker_record_messages, args=(path, thread_id, worker_id, n_per_worker))
        for worker_id in range(n_workers)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)
        assert p.exitcode == 0

    record = ThreadStore(path).get(thread_id)
    assert len(record.messages) == n_workers * n_per_worker  # every append survived
    nonces = {m.nonce for m in record.messages}
    expected = {f"{w}-{i}" for w in range(n_workers) for i in range(n_per_worker)}
    assert nonces == expected
