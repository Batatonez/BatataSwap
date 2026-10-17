from concurrent.futures import ThreadPoolExecutor

from batataswap.auth.ratelimit import Budget, CreationRate, ScryptSlot


def test_budget():
    now = [0.0]
    budget = Budget(max_failures=2, window=10, max_lockout=25, clock=lambda: now[0])
    for delay in (10, 20, 25, 25):
        budget.fail("global")
        assert budget.check("global") == 0
        budget.fail("global")
        assert budget.check("global") == delay
        assert budget.check("device:abc") == 0
        budget.fail("global")  # Não prolonga um bloqueio vigente.
        now[0] += delay
    budget.success("global")
    budget.fail("global")
    budget.fail("global")
    assert budget.check("global") == 10
    budget.reset()
    assert budget.check("global") == 0


def test_sliding_window_and_reset():
    now = [0]
    budget = Budget(max_failures=2, window=10, clock=lambda: now[0])
    budget.fail("global")
    now[0] = 10
    budget.fail("global")
    assert budget.check("global") == 0
    budget.fail("device:abc")
    budget.fail("device:abc")
    assert budget.check("device:abc") == 10
    budget.reset("device:abc")
    assert budget.check("device:abc") == 0


def test_creation_atomic():
    now = [0]
    rate = CreationRate(30, 600, clock=lambda: now[0])
    with ThreadPoolExecutor(8) as pool:
        assert sum(pool.map(lambda _: rate.allow(), range(100))) == 30
    assert rate.check() == 600
    now[0] = 600
    assert rate.check() == 0
    assert rate.allow()


def test_scrypt_slot():
    slot = ScryptSlot(timeout=0)
    assert slot.acquire()
    with ThreadPoolExecutor(1) as pool:
        assert not pool.submit(slot.acquire, 0.01).result()
    slot.release()
    assert slot.acquire(0)
    slot.release()


def test_penalty_decay():
    now = [0]
    budget = Budget(max_failures=1, window=10, max_lockout=40, clock=lambda: now[0])
    budget.fail("a")
    now[0] = 10
    budget.fail("a")
    assert budget.check("a") == 20
    now[0] = 91
    budget.fail("a")
    assert budget.check("a") == 10


def test_begin_atomic_and_success():
    budget = Budget(max_failures=1)
    with ThreadPoolExecutor(16) as pool:
        results = list(pool.map(lambda _: budget.begin("a"), range(32)))
    reservations = [r for r in results if not isinstance(r, int)]
    assert len(reservations) == 1
    reservations[0].success()
    assert budget.check("a") == 0


def test_scrypt_queue_limit():
    from threading import Event, Lock

    slot = ScryptSlot()
    queued = Event()
    release = Event()
    guard = Lock()
    waiting = [0]

    class HeldSemaphore:
        def acquire(self, *, blocking=True, timeout=None):
            if not blocking:
                return False
            with guard:
                waiting[0] += 1
                if waiting[0] == 4:
                    queued.set()
            assert release.wait(5)
            return False

    slot._semaphore = HeldSemaphore()
    with ThreadPoolExecutor(4) as pool:
        futures = [pool.submit(slot.acquire) for _ in range(4)]
        try:
            assert queued.wait(5)
            assert slot.acquire() is False
            assert waiting[0] == 4
        finally:
            release.set()
        assert all(f.result() is False for f in futures)


def test_reservation_does_not_clear_after_reset():
    budget = Budget(max_failures=1)
    old = budget.begin("global")
    budget.reset()
    budget.begin("global")
    old.success()
    assert budget.check("global") > 0
