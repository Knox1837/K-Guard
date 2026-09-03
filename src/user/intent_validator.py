"""
Compatibility facade for the pluggable intent-validation core.

graphengine.py and graphengine_live.py keep importing this module, but the
real backend logic now lives in intent_validation_core.py so the validation
strategy can be swapped without changing the public API.
"""
from __future__ import annotations

from intent_validation_core import *  # noqa: F401,F403


if __name__ == "__main__":
    cases = [
        (100, "/home/user/.ssh/id_rsa", None, False),
        (101, "/home/user/project/main.py", "Refactor the main entrypoint", False),
        (102, "/home/user/.ssh/id_rsa", "Refactor the main entrypoint", True),
        (103, "/home/user/.ssh/id_rsa", "Rotate the deploy SSH key", False),
        (104, "/etc/shadow", "List running docker containers", True),
        (105, "/opt/app/.env", "Load the .env file to check DB config", False),
        (106, "/opt/app/.env", "List running docker containers", True),
    ]

    passed = 0
    for pid, path, task, expect_violation in cases:
        result = validate_open_event(pid, path, task)
        got_violation = result is not None
        status = "PASS" if got_violation == expect_violation else "FAIL"
        passed += status == "PASS"
        print(
            f"[{status}] pid={pid} path={path!r} task={task!r} "
            f"-> violation={got_violation}" + (f" ({result.pattern})" if result else "")
        )

    print(f"\n{passed}/{len(cases)} self-test cases passed.")
