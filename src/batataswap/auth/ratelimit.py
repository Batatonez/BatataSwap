"""Orçamentos em memória, sem IP, e exclusão mútua do scrypt."""

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class _State:
    failures: deque = field(default_factory=deque)
    lock_until: float = 0
    penalty: float = 0


class Budget:
    def __init__(self, max_failures=5, window=900, max_lockout=6 * 3600, *, clock=time.monotonic):
        if max_failures <= 0 or window <= 0 or max_lockout <= 0:
            raise ValueError("Limites inválidos.")
        self.max_failures = max_failures
        self.window = window
        self.max_lockout = max_lockout
        self._clock = clock
        self._lock = threading.Lock()
        self._states = {}

    def check(self, key):
        with self._lock:
            state = self._states.get(key)
            return max(0, math.ceil(state.lock_until - self._clock())) if state else 0

    def fail(self, key):
        with self._lock:
            now = self._clock()
            state = self._states.setdefault(key, _State())
            if state.lock_until > now:
                return
            while state.failures and state.failures[0] <= now - self.window:
                state.failures.popleft()
            state.failures.append(now)
            if len(state.failures) >= self.max_failures:
                state.penalty = min(self.max_lockout, state.penalty * 2 or self.window)
                state.lock_until = now + state.penalty
                state.failures.clear()

    def success(self, key):
        self.reset(key)

    def reset(self, key=None):
        """Sem chave, limpa todos os orçamentos (CLI unlock)."""
        with self._lock:
            if key is None:
                self._states.clear()
            else:
                self._states.pop(key, None)


class CreationRate:
    """Janela deslizante; allow reserva um evento atomicamente."""

    def __init__(self, max_events=30, window=600, *, clock=time.monotonic):
        if max_events <= 0 or window <= 0:
            raise ValueError("Limites inválidos.")
        self.max_events = max_events
        self.window = window
        self._clock = clock
        self._events = deque()
        self._lock = threading.Lock()

    def _prune(self, now):
        while self._events and self._events[0] <= now - self.window:
            self._events.popleft()

    def check(self):
        with self._lock:
            now = self._clock()
            self._prune(now)
            if len(self._events) < self.max_events:
                return 0
            return max(0, math.ceil(self._events[0] + self.window - now))

    def allow(self):
        with self._lock:
            now = self._clock()
            self._prune(now)
            if len(self._events) >= self.max_events:
                return False
            self._events.append(now)
            return True


class ScryptSlot:
    """Usar em worker thread; nunca bloquear o event loop com hash ou espera."""

    def __init__(self, timeout=5):
        self.timeout = timeout
        self._semaphore = threading.Semaphore(1)

    def acquire(self, timeout=None) -> bool:
        return self._semaphore.acquire(timeout=self.timeout if timeout is None else timeout)

    def release(self):
        self._semaphore.release()
