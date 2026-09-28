"""
Step 4.5 — Evaluation harness (proposal §8).

Runs the analyzer against a tagged fixture and measures detection quality:

  * true positives  — flagged AND should escalate
  * false positives — flagged but should NOT (the number we most want at zero)
  * false negatives — should escalate but was missed
  * precision / recall
  * rule coverage   — how many of the 23 rules actually fired

Each fixture identity carries "expect": true/false as ground truth.

Run:  python3 evaluate.py fixtures/vulnerable.json
      python3 evaluate.py fixtures/clean.json
"""

import json
import sys

from graph_analyser import load_identities, build_graph, find_escalations
from rules import _RULES, is_admin, registered_rules


def evaluate(path):
    raw = json.loads(open(path).read())
    expect = {i["name"] for i in raw["identities"] if i.get("expect")}

    identities = load_identities(path)
    g = build_graph(identities)
    flagged = {p[0] for p in find_escalations(g, identities)}

    tp = flagged & expect
    fp = flagged - expect
    fn = expect - flagged
    tn = {i["name"] for i in raw["identities"]} - flagged - expect

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 1.0

    # which rules fired at least once on this account?
    fired = set()
    for name, idn in identities.items():
        if is_admin(idn):
            continue
        for r in _RULES:
            for _edge in r(name, idn, identities):
                fired.add(r.__name__)
                break

    print(f"=== Evaluation: {path} ===")
    print(f"  identities:        {len(raw['identities'])}")
    print(f"  expected escals:   {len(expect)}")
    print(f"  flagged by tool:   {len(flagged)}")
    print()
    print(f"  true  positives:   {len(tp)}")
    print(f"  false positives:   {len(fp)}   {sorted(fp) if fp else ''}")
    print(f"  false negatives:   {len(fn)}   {sorted(fn) if fn else ''}")
    print(f"  true  negatives:   {len(tn)}")
    print()
    print(f"  precision:         {precision:.0%}")
    print(f"  recall:            {recall:.0%}")
    print()
    print(f"  rule coverage:     {len(fired)}/{len(_RULES)} rules fired")
    # Only flag un-exercised rules on a fixture that HAS planted attacks; a clean
    # baseline is supposed to fire nothing.
    if expect:
        missed = [r for r in registered_rules() if r not in fired]
        if missed:
            print(f"  rules not exercised: {missed}")
    print()
    return len(fp), len(fn)


if __name__ == "__main__":
    files = sys.argv[1:] or ["fixtures/vulnerable.json", "fixtures/clean.json"]
    total_fp = total_fn = 0
    for f in files:
        fp, fn = evaluate(f)
        total_fp += fp
        total_fn += fn
    print("=" * 40)
    print(f"TOTAL false positives: {total_fp}   false negatives: {total_fn}")
    sys.exit(1 if (total_fp or total_fn) else 0)
