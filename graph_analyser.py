"""
Build the control graph and search it for privilege-escalation paths.

An edge A -> B means "A can end up acting as B".
An escalation is any path from an identity to the ADMIN node.

Run:  python graph_analyser.py [account.json]
"""

import json
import sys

import networkx as nx

from parser import parse
from rules import _RULES, ADMIN, is_admin
from scoring import severity


def load_identities(path):
    with open(path) as f:
        data = json.load(f)
    return {
        item["name"]: {
            "type": item["type"],
            "statements": parse(item["policy"]),
            "trust_policy": item.get("trust_policy"),
        }
        for item in data["identities"]
    }


def build_graph(identities):
    graph = nx.DiGraph()
    graph.add_node(ADMIN, type="target")
    for name, identity in identities.items():
        graph.add_node(name, type=identity["type"])

    for name, identity in identities.items():
        if is_admin(identity):
            graph.add_edge(name, ADMIN, label="is administrator")
            continue
        for rule in _RULES:
            for target, label in rule(name, identity, identities):
                graph.add_edge(name, target, label=label)

    return graph


def find_escalations(graph, identities):
    """Shortest path to admin for every identity that is not already admin."""
    paths = [
        nx.shortest_path(graph, name, ADMIN)
        for name, identity in identities.items()
        if not is_admin(identity) and nx.has_path(graph, name, ADMIN)
    ]
    return sorted(paths, key=len)


def path_severity(path):
    return severity(len(path) - 1, "admin")


def describe(graph, path):
    lines = [path[0]]
    for source, target in zip(path, path[1:]):
        label = graph.edges[source, target]["label"]
        node = "effective ADMIN" if target == ADMIN else target
        lines.append(f"        --[ {label} ]-->  {node}")
    return "\n".join(lines)


def print_report(graph, paths):
    print(
        f"Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges, "
        f"{len(_RULES)} rules\n"
    )
    if not paths:
        print("No escalation paths found.")
        return
    print(f"{len(paths)} identit(ies) can reach ADMIN:\n")
    for path in paths:
        print(
            f"  [{path_severity(path):6}] ({len(path) - 1}-hop) {describe(graph, path)}\n"
        )


if __name__ == "__main__":
    account_file = sys.argv[1] if len(sys.argv) > 1 else "account.json"
    identities = load_identities(account_file)
    graph = build_graph(identities)
    print_report(graph, find_escalations(graph, identities))
