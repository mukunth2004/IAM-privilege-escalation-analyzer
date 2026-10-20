"""
Step 4: Risk scoring.

Turn each escalation path into a High / Medium / Low label 
"""


def severity(hops, blast):
    """
    Combine the two dials into one label.
    """
    if blast == "admin":
        # Full admin is dangerous; a short path makes it urgent.
        return "High" if hops <= 2 else "Medium"
    if blast == "write":
        return "Medium" if hops <= 2 else "Low"
    # read-only
    return "Low"
