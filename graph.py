"""
Step 2 + 3 — Build the control graph, then search it for escalation paths.

Control edge  A --> B  means "A can end up acting as B."
Escalation    = a path from an identity to the ADMIN node.
The path search is what finds MULTI-HOP chains no single rule spells out.
"""

import json
import networkx as nx

from parser import parse
from rules import _RULES, ADMIN, is_admin
from scoring import severity


def load_identities(path):
    """Read the account file; parse each policy; keep role trust policies."""
    data = json.loads(open(path).read())
    identities = {}
    for item in data["identities"]:
        identities[item["name"]] = {
            "type": item["type"],
            "statements": parse(item["policy"]),
            "trust_policy": item.get("trust_policy"),   # roles only
        }
    return identities


def build_graph(identities):
    g = nx.DiGraph()
    g.add_node(ADMIN, type="target")
    for name, idn in identities.items():
        g.add_node(name, type=idn["type"])

    for name, idn in identities.items():
        # An already-admin identity just gets a marker edge to ADMIN and is not
        # run through the escalation rules (it has nothing to escalate TO).
        if is_admin(idn):
            g.add_edge(name, ADMIN, label="is administrator")
            continue
        # Run every rule; each yields control edges from this identity.
        for rule_fn in _RULES:
            for target, label in rule_fn(name, idn, identities):
                g.add_edge(name, target, label=label)

    return g


def find_escalations(g, identities):
    """For each non-admin identity, is there a path to ADMIN? If so, return the
    shortest one (fewest hops = easiest for an attacker)."""
    findings = []
    for name, idn in identities.items():
        if is_admin(idn):
            continue
        if nx.has_path(g, name, ADMIN):
            path = nx.shortest_path(g, name, ADMIN)
            findings.append(path)
    # most direct chains first
    findings.sort(key=len)
    return findings


def describe(g, path):
    """Render a path as a readable chain with the permission on each hop."""
    out = path[0]
    for a, b in zip(path, path[1:]):
        label = g.edges[a, b]["label"]
        node = "effective ADMIN" if b == ADMIN else b
        out += f"\n        --[ {label} ]-->  {node}"
    return out


if __name__ == "__main__":
    identities = load_identities("account.json")
    g = build_graph(identities)

    print(f"Graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges, "
          f"{len(_RULES)} rules\n")

    findings = find_escalations(g, identities)
    if not findings:
        print("No escalation paths found.")
    else:
        print(f"{len(findings)} identit(ies) can reach ADMIN:\n")
        for path in findings:
            hops = len(path) - 1
            # Every path here ends at ADMIN, so its blast radius is full admin.
            label = severity(hops, "admin")
            print(f"  [{label:6}] ({hops}-hop) {describe(g, path)}\n")
