"""
Draw the identity graph to a PNG, with escalation paths coloured by severity.

Run:  python visualize.py [account.json] [out.png]
"""

import sys

import matplotlib
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import networkx as nx

from graph_analyser import load_identities, build_graph, find_escalations, path_severity
from rules import ADMIN

matplotlib.use("Agg")

NODE_SHAPES = {"user": "o", "role": "s", "group": "h", "target": "D"}
NODE_COLORS = {
    "user": "#6FA8DC",
    "role": "#93C47D",
    "group": "#B4A7D6",
    "target": "#7B0828",
}
SEVERITY_COLORS = {"High": "#E82525", "Medium": "#F5A623", "Low": "#9AA0A6"}
SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3}
OTHER_EDGE_COLOR = "#C8C8C8"
NODE_SIZE = 1400
EDGE_CURVE = "arc3"


def worst_severity_per_edge(paths):
    edge_severity = {}
    for path in paths:
        severity = path_severity(path)
        for edge in zip(path, path[1:]):
            current = edge_severity.get(edge)
            if SEVERITY_RANK[severity] > SEVERITY_RANK.get(current, 0):
                edge_severity[edge] = severity
    return edge_severity


def nodes_of_type(graph, *types):
    return [n for n, data in graph.nodes(data=True) if data["type"] in types]


def ring_layout(graph):
    """ADMIN in the centre, roles and groups on the inner ring, users on the outer ring."""
    rings = [
        [ADMIN],
        nodes_of_type(graph, "role", "group"),
        nodes_of_type(graph, "user"),
    ]
    return nx.shell_layout(graph, nlist=[ring for ring in rings if ring])


def draw_nodes(graph, pos, ax):
    for node_type, shape in NODE_SHAPES.items():
        nodes = nodes_of_type(graph, node_type)
        if nodes:
            nx.draw_networkx_nodes(
                graph,
                pos,
                nodelist=nodes,
                node_shape=shape,
                node_color=NODE_COLORS[node_type],
                node_size=NODE_SIZE,
                edgecolors="white",
                linewidths=1.5,
                ax=ax,
            )

    identity_labels = {n: n for n in graph if n != ADMIN}
    nx.draw_networkx_labels(
        graph, pos, labels=identity_labels, font_size=8, font_weight="bold", ax=ax
    )
    nx.draw_networkx_labels(
        graph,
        pos,
        labels={ADMIN: ADMIN},
        font_size=8,
        font_weight="bold",
        font_color="white",
        ax=ax,
    )


def draw_edges(graph, pos, edge_severity, ax):
    for edge in graph.edges():
        severity = edge_severity.get(edge)
        nx.draw_networkx_edges(
            graph,
            pos,
            edgelist=[edge],
            node_size=NODE_SIZE,
            edge_color=SEVERITY_COLORS[severity] if severity else OTHER_EDGE_COLOR,
            width=2.4 if severity else 1.0,
            arrowsize=15,
            connectionstyle=EDGE_CURVE,
            ax=ax,
        )

    permission_labels = {
        (source, target): data["label"].split(" (")[0].replace(" + ", "\n+ ")
        for source, target, data in graph.edges(data=True)
    }
    nx.draw_networkx_edge_labels(
        graph,
        pos,
        edge_labels=permission_labels,
        font_size=6,
        rotate=False,
        connectionstyle=EDGE_CURVE,
        bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.8),
        ax=ax,
    )


def draw_legend(ax):
    node_entries = [
        Line2D(
            [0],
            [0],
            marker=shape,
            color="w",
            markerfacecolor=NODE_COLORS[node_type],
            markersize=12,
            label="ADMIN" if node_type == "target" else node_type,
        )
        for node_type, shape in NODE_SHAPES.items()
    ]
    edge_entries = [
        Line2D([0], [0], color=color, lw=3, label=f"{severity} severity path")
        for severity, color in SEVERITY_COLORS.items()
    ]
    edge_entries.append(
        Line2D([0], [0], color=OTHER_EDGE_COLOR, lw=1.5, label="other relationship")
    )
    ax.legend(handles=node_entries + edge_entries, loc="upper left", fontsize=8)


def render(account_file, out_png):
    identities = load_identities(account_file)
    graph = build_graph(identities)
    paths = find_escalations(graph, identities)

    fig, ax = plt.subplots(figsize=(14, 11))
    pos = ring_layout(graph)
    draw_nodes(graph, pos, ax)
    draw_edges(graph, pos, worst_severity_per_edge(paths), ax)
    draw_legend(ax)

    ax.set_title(
        f"IAM identity graph — {account_file}\n"
        f"{len(paths)} escalation paths to ADMIN"
    )
    ax.margins(0.08)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(out_png, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out_png}  ({len(paths)} paths drawn)")


if __name__ == "__main__":
    account_file = sys.argv[1] if len(sys.argv) > 1 else "account.json"
    out_png = sys.argv[2] if len(sys.argv) > 2 else "escalation_graph.png"
    render(account_file, out_png)
