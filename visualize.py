"""
Step 5 — Visualization.

Renders the identity graph with escalation paths highlighted by severity
(proposal §6.2): nodes are identities, edges are control relationships, and every
edge on a detected escalation path is colored by that path's severity label
(red = High, amber = Medium, gray = Low) and annotated with the IAM permission
that enables the hop. A legend makes the encoding explicit.

Run:  python3 visualize.py [account.json] [out.png]
"""

import sys

import matplotlib
matplotlib.use("Agg")            # render to a file, no display needed
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
import networkx as nx

from graph import load_identities, build_graph, find_escalations
from rules import ADMIN, is_admin
from scoring import severity

SEV_COLOR = {"High": "#E4572E", "Medium": "#F5A623", "Low": "#9AA0A6"}
STRUCTURAL = "#D0D0D0"


def _severity_of_path(path):
    return severity(len(path) - 1, "admin")   # every path here ends at full admin


def render(account_file, out_png):
    identities = load_identities(account_file)
    g = build_graph(identities)
    paths = find_escalations(g, identities)

    # Work out the worst severity touching each edge and each node.
    edge_sev, node_sev = {}, {}
    order = {"Low": 1, "Medium": 2, "High": 3}
    for path in paths:
        sev = _severity_of_path(path)
        for n in path:
            if order.get(sev, 0) > order.get(node_sev.get(n, "none"), 0):
                node_sev[n] = sev
        for a, b in zip(path, path[1:]):
            if order.get(sev, 0) > order.get(edge_sev.get((a, b), "none"), 0):
                edge_sev[(a, b)] = sev

    pos = nx.spring_layout(g, seed=42, k=1.3, iterations=200)

    fig, ax = plt.subplots(figsize=(15, 10))

    # ---- nodes ----
    for n, attrs in g.nodes(data=True):
        if n == ADMIN:
            color, shape, size = "#7B0828", "s", 2600
        elif n in node_sev:
            color, shape, size = SEV_COLOR[node_sev[n]], "o", 2000
        else:
            color, shape, size = "#B7C4CF", "o", 1500     # not on any path
        nx.draw_networkx_nodes(g, pos, nodelist=[n], node_color=color,
                               node_shape=shape, node_size=size, ax=ax,
                               edgecolors="white", linewidths=1.5)

    # ---- edges ----
    for a, b in g.edges():
        color = SEV_COLOR[edge_sev[(a, b)]] if (a, b) in edge_sev else STRUCTURAL
        width = 2.6 if (a, b) in edge_sev else 1.0
        nx.draw_networkx_edges(g, pos, edgelist=[(a, b)], edge_color=color,
                               width=width, arrowsize=18, ax=ax,
                               min_source_margin=18, min_target_margin=18)

    # ---- labels ----
    labels = {n: ("ADMIN" if n == ADMIN else n) for n in g.nodes()}
    nx.draw_networkx_labels(g, pos, labels=labels, font_size=8,
                            font_weight="bold", font_color="#1a1a1a", ax=ax)
    edge_labels = {(a, b): g.edges[a, b]["label"].split(" (")[0] for a, b in g.edges()}
    nx.draw_networkx_edge_labels(g, pos, edge_labels=edge_labels, font_size=6,
                                 font_color="#444", ax=ax, rotate=False,
                                 bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.7))

    legend = [
        Patch(facecolor="#7B0828", label="ADMIN (full control)"),
        Line2D([0], [0], color=SEV_COLOR["High"], lw=3, label="High severity path"),
        Line2D([0], [0], color=SEV_COLOR["Medium"], lw=3, label="Medium severity path"),
        Line2D([0], [0], color=STRUCTURAL, lw=2, label="other relationship"),
        Patch(facecolor="#B7C4CF", label="no escalation path"),
    ]
    ax.legend(handles=legend, loc="upper left", fontsize=9, frameon=True)

    n_high = sum(1 for p in paths if _severity_of_path(p) == "High")
    n_med = sum(1 for p in paths if _severity_of_path(p) == "Medium")
    ax.set_title(f"IAM Privilege-Escalation Graph — {account_file}\n"
                 f"{len(paths)} escalation paths to admin  "
                 f"({n_high} High, {n_med} Medium)", fontsize=13)
    ax.axis("off")
    plt.tight_layout()
    plt.savefig(out_png, dpi=150, bbox_inches="tight")
    print(f"wrote {out_png}  ({len(paths)} paths drawn)")


if __name__ == "__main__":
    account_file = sys.argv[1] if len(sys.argv) > 1 else "account.json"
    out_png = sys.argv[2] if len(sys.argv) > 2 else "escalation_graph.png"
    render(account_file, out_png)
