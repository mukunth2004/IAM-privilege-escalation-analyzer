# Parser for AWS IAM policy documents
# parse() turns policy JSON into Statements and allows() checks if an action is permitted

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache


@dataclass
class Statement:
    # One normalized IAM statement

    effect: str            # 'Allow' or 'Deny'
    actions: list[str]     # always a list, even for a single action
    resources: list[str]   # always a list
    not_actions: list[str] = field(default_factory=list)    # from NotAction
    not_resources: list[str] = field(default_factory=list)  # from NotResource
    condition: dict | None = None                           # raw Condition that is not evaluated


def parse(document: dict) -> list[Statement]:
    # Convert a policy document into a list of 'Statements'
    # 'Action' and 'Resource' can be a string or a list so both become lists

    statements = []
    for raw in _as_list(document.get("Statement", [])):
        not_resources = _as_list(raw.get("NotResource"))
        default_resources = [] if not_resources else ["*"]
        statements.append(
            Statement(
                effect=raw.get("Effect", "Allow"),
                actions=[a.lower() for a in _as_list(raw.get("Action", []))],
                resources=_as_list(raw.get("Resource", default_resources)),
                not_actions=[a.lower() for a in _as_list(raw.get("NotAction"))],
                not_resources=not_resources,
                condition=raw.get("Condition"),
            )
        )
    return statements


def matches(stmt: Statement, action: str, resource: str) -> bool:
    # Check if one statement covers both the action and the resource

    action_ok = _covers(stmt.actions, stmt.not_actions, action.lower())
    resource_ok = _covers(stmt.resources, stmt.not_resources, resource)
    return action_ok and resource_ok


def allows(statements: list[Statement], action: str, resource: str = "*") -> bool:
    # Check if the statements allow the action on the resource
    # A matching 'Deny' always wins otherwise one matching 'Allow' is enough

    if any(matches(s, action, resource) for s in statements if s.effect == "Deny"):
        return False
    return any(matches(s, action, resource) for s in statements if s.effect == "Allow")


def _covers(patterns: list[str], not_patterns: list[str], value: str) -> bool:
    # Check a value against an Action/Resource list or its Not- version
    # The query '*' means everything, which a Not- list can never fully cover

    if patterns:
        return any(_wildcard_match(value, p) for p in patterns)
    if not_patterns:
        if value == "*":
            return False
        return not any(_wildcard_match(value, p) for p in not_patterns)
    return False  # no action/resource given so nothing matches


def _wildcard_match(value: str, pattern: str) -> bool:
    # IAM wildcard match: '*' is any characters, '?' is exactly one

    return _compile(pattern).fullmatch(value) is not None


@lru_cache(maxsize=None)
def _compile(pattern: str) -> re.Pattern:
    # Convert an IAM wildcard pattern to a regex

    regex = "".join(
        ".*" if ch == "*" else "." if ch == "?" else re.escape(ch)
        for ch in pattern
    )
    return re.compile(regex, re.DOTALL)


def _as_list(x):
    # Wrap a single value in a list
    
    if x is None:
        return []
    return x if isinstance(x, list) else [x]
