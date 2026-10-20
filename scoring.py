"""
Step 4 — Risk scoring.

Turn each escalation path into a High / Medium / Low label using two dials:

  * hops   — number of steps in the chain. Fewer = easier for an attacker = worse.
  * blast  — how much power the chain ends in:
               "admin"  = full control        (worst)
               "write"  = change one service
               "read"   = read-only           (mildest)

The proposal's worked examples we're matching (§6.1):
  * a short chain ending in full admin        -> High
  * a long chain ending in read-only access   -> Low
"""


def severity(hops, blast):
    """Combine the two dials into one label."""
    if blast == "admin":
        # Full admin is dangerous; a short path makes it urgent.
        return "High" if hops <= 2 else "Medium"
    if blast == "write":
        return "Medium" if hops <= 2 else "Low"
    # read-only
    return "Low"
