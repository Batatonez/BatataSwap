from concurrent.futures import ThreadPoolExecutor

from batataswap.auth.owner import unlock
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
    unlock(budget)
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
