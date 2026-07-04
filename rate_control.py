#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Rate Control & Stealth Engine
Provides request jitter, delay randomization, and concurrency limiting.

Usage:
    from rate_control import RateController
    rc = RateController(stealth=True)        # sensible defaults
    rc = RateController(min_delay=2, max_delay=5, max_concurrent=3)  # granular
    rc.wait()                                # call before each request
    sem = rc.semaphore()                     # use for concurrency control
"""

import random, threading, time, argparse


# ── Preset Profiles ──────────────────────────────────────────
PROFILES = {
    "default": {
        "min_delay": 0.0,
        "max_delay": 0.0,
        "max_concurrent": 10,
        "jitter": False,
    },
    "stealth": {
        "min_delay": 1.0,
        "max_delay": 3.0,
        "max_concurrent": 3,
        "jitter": True,
    },
    "aggressive": {
        "min_delay": 0.0,
        "max_delay": 0.1,
        "max_concurrent": 20,
        "jitter": False,
    },
    "paranoid": {
        "min_delay": 3.0,
        "max_delay": 8.0,
        "max_concurrent": 1,
        "jitter": True,
    },
}


class RateController:
    """Controls request timing and concurrency for stealth or performance.

    Parameters
    ----------
    stealth : bool
        Enable stealth mode with sensible defaults (1-3s jitter, 3 concurrent).
    profile : str
        Named preset: 'default', 'stealth', 'aggressive', 'paranoid'.
    min_delay : float
        Minimum delay between requests in seconds (overrides profile).
    max_delay : float
        Maximum delay between requests in seconds (overrides profile).
    max_concurrent : int
        Maximum concurrent requests / threads (overrides profile).
    jitter : bool
        Enable randomised delay (overrides profile).
    """

    def __init__(self, stealth=False, profile=None, min_delay=None,
                 max_delay=None, max_concurrent=None, jitter=None):
        # Resolve base profile
        if profile and profile in PROFILES:
            cfg = dict(PROFILES[profile])
        elif stealth:
            cfg = dict(PROFILES["stealth"])
        else:
            cfg = dict(PROFILES["default"])

        # Granular overrides
        if min_delay is not None:
            cfg["min_delay"] = min_delay
        if max_delay is not None:
            cfg["max_delay"] = max_delay
        if max_concurrent is not None:
            cfg["max_concurrent"] = max_concurrent
        if jitter is not None:
            cfg["jitter"] = jitter

        self.min_delay = cfg["min_delay"]
        self.max_delay = cfg["max_delay"]
        self.max_concurrent = cfg["max_concurrent"]
        self.jitter = cfg["jitter"]
        self._semaphore = threading.Semaphore(self.max_concurrent)
        self._lock = threading.Lock()
        self._request_count = 0

    def wait(self):
        """Sleep for a randomised duration between min_delay and max_delay.

        Call this **before** each outbound request.
        """
        if self.max_delay <= 0:
            return
        if self.jitter:
            delay = random.uniform(self.min_delay, self.max_delay)
        else:
            delay = self.min_delay
        if delay > 0:
            time.sleep(delay)
        with self._lock:
            self._request_count += 1

    def semaphore(self):
        """Return a threading.Semaphore for concurrency control.

        Use as a context manager::

            with rc.semaphore():
                make_request()
        """
        return self._semaphore

    @property
    def request_count(self):
        with self._lock:
            return self._request_count

    @property
    def is_stealth(self):
        return self.max_delay > 0 or self.max_concurrent < 10

    def __repr__(self):
        return (f"RateController(delay={self.min_delay}-{self.max_delay}s, "
                f"concurrent={self.max_concurrent}, jitter={self.jitter})")


def build_rate_controller(args_namespace):
    """Build a RateController from parsed argparse namespace.

    Expects optional attributes: stealth, rate_profile, delay_min,
    delay_max, max_concurrent.
    """
    return RateController(
        stealth=getattr(args_namespace, "stealth", False),
        profile=getattr(args_namespace, "rate_profile", None),
        min_delay=getattr(args_namespace, "delay_min", None),
        max_delay=getattr(args_namespace, "delay_max", None),
        max_concurrent=getattr(args_namespace, "max_concurrent_rate", None),
    )


def add_rate_args(parser):
    """Add rate-control CLI arguments to an argparse parser."""
    grp = parser.add_argument_group("Stealth / Rate Control")
    grp.add_argument("--stealth", action="store_true",
                     help="Enable stealth mode (1-3s jitter, 3 concurrent)")
    grp.add_argument("--rate-profile", default=None,
                     choices=list(PROFILES.keys()),
                     help="Named rate profile")
    grp.add_argument("--delay-min", type=float, default=None,
                     help="Minimum delay between requests (seconds)")
    grp.add_argument("--delay-max", type=float, default=None,
                     help="Maximum delay between requests (seconds)")
    grp.add_argument("--max-concurrent-rate", type=int, default=None,
                     help="Max concurrent requests (rate limiter)")


# ── CLI self-test ────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — Rate Control self-test")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        # Test default profile
        rc = RateController()
        assert rc.max_delay == 0.0
        assert rc.max_concurrent == 10
        rc.wait()  # should return immediately

        # Test stealth profile
        rc2 = RateController(stealth=True)
        assert rc2.min_delay == 1.0
        assert rc2.max_delay == 3.0
        assert rc2.max_concurrent == 3
        assert rc2.is_stealth

        # Test granular overrides
        rc3 = RateController(stealth=True, max_concurrent=5, max_delay=2.0)
        assert rc3.max_concurrent == 5
        assert rc3.max_delay == 2.0

        # Test paranoid profile
        rc4 = RateController(profile="paranoid")
        assert rc4.max_concurrent == 1
        assert rc4.min_delay == 3.0

        print(f"[OK] Rate control self-test passed")
        print(f"  Default:  {RateController()}")
        print(f"  Stealth:  {RateController(stealth=True)}")
        print(f"  Paranoid: {RateController(profile='paranoid')}")
    else:
        print("Usage: python3 rate_control.py --test")
