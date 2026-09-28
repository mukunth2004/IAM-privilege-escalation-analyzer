"""
Step 1 — The Parser.

Turns raw AWS IAM policy JSON into structured permission-facts we can query.

Two layers, exactly as we reasoned about them:
  * matches()  -> does ONE statement cover this action + resource? (wildcards)
  * allows()   -> does the WHOLE pile allow it? (Deny overrides, else any Allow)
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass


@dataclass
class Statement:
    """One normalized IAM statement: (effect, actions, resources)."""
    effect: str            # "Allow" or "Deny"
    actions: list[str]     # always a list, even for a single action
    resources: list[str]   # always a list


def parse(document: dict) -> list[Statement]:
    """Flatten an IAM policy document into a list of Statement objects.

    We absorb AWS's irregularity here at the boundary: Action and Resource can
    each be a single string OR a list, so we force both to lists. Every later
    stage then gets clean, uniform data.
    """
    statements = []
    for raw in _as_list(document.get("Statement", [])):
        statements.append(
            Statement(
                effect=raw.get("Effect", "Allow"),
                actions=[a.lower() for a in _as_list(raw.get("Action", []))],
                resources=_as_list(raw.get("Resource", ["*"])),
            )
        )
    return statements


def matches(stmt: Statement, action: str, resource: str) -> bool:
    """Does a SINGLE statement cover this action AND this resource?

    Both checks use fnmatch so wildcards work: 'iam:*' covers 'iam:passrole',
    and '*' covers anything. This is the AND you reasoned out — miss either
    check and the statement doesn't apply.
    """
    action = action.lower()
    action_ok = any(fnmatch.fnmatch(action, pat) for pat in stmt.actions)
    resource_ok = any(fnmatch.fnmatch(resource, pat) for pat in stmt.resources)
    return action_ok and resource_ok


def allows(statements: list[Statement], action: str, resource: str = "*") -> bool:
    """Does the whole set of statements allow this action on this resource?

    AWS evaluation model:
        default deny  ->  an explicit Allow grants (one is enough)
                      ->  an explicit Deny overrides everything.
    So: if ANY Deny matches, blocked. Otherwise, if ANY Allow matches, granted.
    """
    if any(matches(s, action, resource) for s in statements if s.effect == "Deny"):
        return False
    return any(matches(s, action, resource) for s in statements if s.effect == "Allow")


def _as_list(x):
    """None -> [], a single value -> [value], a list stays a list."""
    if x is None:
        return []
    return x if isinstance(x, list) else [x]
