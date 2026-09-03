"""
intent_validator.py: Section 3.6.3 Intent Validation Algorithm.

Pure, dependency-free comparison logic for K-Guard's Intent-Aware Pipeline
(Methodology Section 3.6). Deliberately kept in its own module, separate
from graphengine.py / graphengine_live.py, for two reasons:

1. It's the one piece of the Intent-Aware Pipeline that's pure Python with
   no eBPF/root/live-monitor dependency, so it can be fully unit tested in
   isolation (see the __main__ self-test block at the bottom).
2. graphengine.py and graphengine_live.py already duplicate their event
   handlers independently (see AGENTS.md invariant #2), this module gives
   both a single shared implementation of the validation *algorithm*
   itself, so a future retune of the matching logic only has to happen
   once.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Section 3.6.3 step 2: sensitive path patterns. A path is "sensitive" if
# any of these substrings appears anywhere in it.
SENSITIVE_PATH_PATTERNS = [".ssh/", "/etc/shadow", ".gnupg/", ".env", "credentials"]

# Section 3.6.3 step 3 asks whether the sensitive path is "referenced in
# the task description" but the paper doesn't pin down the exact matching
# algorithm. This module makes that explicit: for each sensitive pattern,
# a curated set of plain-English keywords that would plausibly appear in a
# legitimate task description referencing that kind of file.
_PATTERN_KEYWORDS = {
    ".ssh/": ("ssh", "id_rsa", "id_ed25519", "known_hosts", "authorized_keys", "ssh key"),
    "/etc/shadow": ("shadow", "password hash", "/etc/shadow"),
    ".gnupg/": ("gnupg", "gpg", "pgp key"),
    ".env": (".env", "environment variable", "env file", "dotenv"),
    "credentials": ("credential", "api key", "secret", "token"),
}


def is_sensitive_path(path: str) -> Optional[str]:
    """Return the matching sensitive-pattern string, or None if `path` isn't sensitive."""
    if not path:
        return None
    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern in path:
            return pattern
    return None


def path_referenced_in_intent(path: str, task_description: str, pattern: str) -> bool:
    """
    True if `task_description` plausibly justifies opening `path`, which
    matched sensitive `pattern`. Checks, in order:
      (a) the pattern's own text appearing literally in the task description,
      (b) the file's basename appearing literally in the task description,
      (c) the curated keyword set for that pattern (_PATTERN_KEYWORDS).
    """
    if not task_description:
        return False
    text = task_description.lower()

    if pattern.strip("/.").lower() in text:
        return True

    basename = path.rsplit("/", 1)[-1].lower()
    if basename and basename in text:
        return True

    for kw in _PATTERN_KEYWORDS.get(pattern, ()):
        if kw.lower() in text:
            return True

    return False


@dataclass
class IntentViolation:
    """Result of a failed Section 3.6.3 validation, ready to be attached to a graph node."""
    pid: int
    path: str
    pattern: str
    task_description: str

    def as_dict(self) -> dict:
        return {
            "pid": self.pid,
            "path": self.path,
            "matched_pattern": self.pattern,
            "task_description": self.task_description,
        }


def validate_open_event(
    pid: int, path: str, task_description: Optional[str]
) -> Optional[IntentViolation]:
    """
    Implements Section 3.6.3's three-step algorithm for a single FILE_OPEN
    event.

    Args:
        pid: PID that issued the open().
        path: the path that was opened.
        task_description: the declared intent for `pid` from intent_map,
            or None if this PID has no registered intent at all.

    Returns:
        An IntentViolation if this event should raise INTENT_VIOLATION,
        else None.
    """
    # Step 1: no intent entry registered for this PID -> this event is not
    # this pipeline's concern at all; it still goes through the standard,
    # non-intent anomaly detection pipeline (graphengine.py's existing
    # SENSITIVE_DIRECTORIES/SENSITIVE_KEYWORDS handling).
    if task_description is None:
        return None

    # Step 2: is the opened path sensitive at all?
    pattern = is_sensitive_path(path)
    if pattern is None:
        return None

    # Step 3: is it justified by the declared task?
    if path_referenced_in_intent(path, task_description, pattern):
        return None

    return IntentViolation(pid=pid, path=path, pattern=pattern, task_description=task_description)


if __name__ == "__main__":
    # Lightweight self-test — runs with no dependencies, no root, no eBPF.
    # This is the part of the Intent-Aware Pipeline that's actually
    # exercised in environments without a real K-Guard/eBPF host.
    cases = [
        # (pid, path, task_description, expect_violation)
        (100, "/home/user/.ssh/id_rsa", None, False),  # no intent entry -> not our concern
        (101, "/home/user/project/main.py", "Refactor the main entrypoint", False),  # not sensitive
        (102, "/home/user/.ssh/id_rsa", "Refactor the main entrypoint", True),  # sensitive, unjustified
        (103, "/home/user/.ssh/id_rsa", "Rotate the deploy SSH key", False),  # justified
        (104, "/etc/shadow", "List running docker containers", True),  # sensitive, unjustified
        (105, "/opt/app/.env", "Load the .env file to check DB config", False),  # justified
        (106, "/opt/app/.env", "List running docker containers", True),  # sensitive, unjustified
    ]

    passed = 0
    for pid, path, task, expect_violation in cases:
        result = validate_open_event(pid, path, task)
        got_violation = result is not None
        status = "PASS" if got_violation == expect_violation else "FAIL"
        passed += status == "PASS"
        print(f"[{status}] pid={pid} path={path!r} task={task!r} "
              f"-> violation={got_violation}" + (f" ({result.pattern})" if result else ""))

    print(f"\n{passed}/{len(cases)} self-test cases passed.")
