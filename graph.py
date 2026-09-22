import matplotlib.pyplot as plt
import networkx as nx

# TODO: replace with the json parser output
IDENTITIES = {
    "user-A": ["lambda:CreateFunction", "iam:PassRole"],
    "lambda-exec-role": ["*"],
    "user-B": ["s3:GetObject"],
}


def build_graph(identities):
    g = nx.DiGraph()
    for name, permissions in identities.items():
        g.add_node(name, permissions=permissions)

    for name, permissions in identities.items():
        if "iam:PassRole" in permissions and "lambda:CreateFunction" in permissions:
            for target, target_permissions in identities.items():
                if target != name and "*" in target_permissions:
                    g.add_edge(name, target, permission="lambda:CreateFunction + iam:PassRole")
        # TODO: add more rules for other types of privilege escalation
    return g


def visualise(g, path=None):
    pos = nx.spring_layout(g, seed=1)
    nx.draw_networkx_nodes(g, pos, node_color="lightsteelblue", node_size=2500)
    nx.draw_networkx_labels(g, pos, font_size=8)
    nx.draw_networkx_edges(g, pos, edge_color="black", width=1, node_size=2500)
    labels = {(u, v): d["permission"].replace(" + ", "\n+ ") for u, v, d in g.edges(data=True)}
    nx.draw_networkx_edge_labels(
        g,
        pos,
        edge_labels=labels,
        font_size=7,
        rotate=False,
    )
    plt.title("IAM identity graph")
    plt.margins(0.15)
    plt.axis("off")
    plt.tight_layout()
    if path:
        plt.savefig(path, dpi=150)
    else:
        plt.show()


if __name__ == "__main__":
    graph = build_graph(IDENTITIES)
    print(f"{graph.number_of_nodes()} identities, {graph.number_of_edges()} edges")
    for source, target, data in graph.edges(data=True):
        print(f"  {source} -> {target}  via {data['permission']}")
    visualise(graph)
