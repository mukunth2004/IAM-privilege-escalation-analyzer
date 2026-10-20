# IAM Privilege-Escalation Graph Analyzer

Detect hidden privilege-escalation paths in AWS IAM through graph-based analysis.

IAM permissions are usually reviewed one policy at a time, but real escalation
comes from *combinations* of individually reasonable-looking permissions spread
across users, roles, and groups. This tool models an account as a directed graph
of "who can gain control over whom" and searches it for paths that end in
administrator access.

> Course project for DD2391 / DD2394 (Cybersecurity Overview / Cybersecurity
> Project), KTH Royal Institute of Technology.

![Escalation graph — escalation paths highlighted by severity](docs/example_full.png)

*Escalation paths detected in a sample account: red = High, amber = Medium, gray = no path; each edge is labeled with the IAM permission that enables the hop.*

## Features

**23 escalation techniques** in five families: policy self-grant, credential
theft, trust-policy manipulation, PassRole-to-compute, and role chaining. The
catalogue is the one from Rhino Security Labs, which PMapper and Pacu also
implement.

**Multi-hop detection.** Escalation is a path search to an `ADMIN` node, so
chains that no single rule describes (assume a role that can then make itself
admin) come out of the search for free. Only the shortest path per identity is
reported, so an identity with two routes to admin will only show one of them.

**Risk scoring.** Each path is labeled High, Medium or Low. In practice the
label is decided by hop count alone: 1-2 hops is High, 3 or more is Medium.
`scoring.severity()` takes a second blast-radius argument (read, write, admin),
but every finding is by definition a path to admin, so `graph_analyser` always
passes `"admin"` and the other two levels never come up in a normal run.

**Graph visualization.** Findings render to a PNG with severity-colored edges,
each labeled with the permission that enables the hop.

**Evaluation harness.** `evaluate.py` scores the rules against the fixtures and
exits nonzero on any false positive or negative, so it works as a CI gate. See
[Testing](#testing) for what the numbers do and do not show.

## Pipeline

| Stage | File | What it does |
|-------|------|--------------|
| 1. Parse | `parser.py` | IAM policy JSON → queryable permission facts (`allows()`) |
| 2. Graph | `graph_analyser.py` | build the "who can control whom" graph + path search |
| 3. Rules | `rules.py` | 23 escalation-technique rules |
| 4. Score | `scoring.py` | High / Medium / Low per path |
| 5. Visualize | `visualize.py` | render the severity graph to PNG |

The numbering follows the order the stages were built, not the call order at
runtime: `build_graph()` runs every rule to produce the edges, so stage 3 is
what stage 2 consumes.

## Install

```bash
git clone <your-repo-url>
cd IAM-privilege-escalation-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`networkx` is required for the graph search, `matplotlib` only for the
visualization. The parser, the rules and the scoring have no third-party
dependencies.

## Usage

```bash
# Detect escalation paths in an account and print them, ranked by severity
python3 graph_analyser.py account_full.json

# Render the findings as a colored graph
python3 visualize.py account.json escalation_graph.png

# Run the evaluation harness (precision / recall / false positives)
python3 evaluate.py
```

### Input format

A single JSON file describing an account's identities and their policies — a
simplified shape of `aws iam get-account-authorization-details`:

```json
{
  "account_id": "123456789012",
  "identities": [
    {
      "name": "alice",
      "type": "user",
      "policy": { "Statement": [
        { "Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": "*" },
        { "Effect": "Allow", "Action": "iam:PassRole",
          "Resource": "arn:aws:iam::123456789012:role/admin-role" }
      ] }
    }
  ]
}
```

Roles may also carry a `trust_policy`. See `fixtures/` and the sample
`account.json` / `account_full.json` for worked examples. Identities in the
fixtures carry an extra `expect` flag, which is ground truth for `evaluate.py`
and is ignored everywhere else.

### Example output

```
  [High  ] (2-hop) alice
        --[ iam:PassRole + lambda:CreateFunction (run as admin-role via lambda) ]-->  admin-role
        --[ is administrator ]-->  effective ADMIN

  [Medium] (3-hop) dave
        --[ sts:AssumeRole ]-->  stage-role
        --[ sts:AssumeRole ]-->  deploy-role
        --[ iam:AttachRolePolicy (attach AdministratorAccess to self) ]-->  effective ADMIN
```

## Escalation techniques

| Family | Rules |
|--------|-------|
| A — Policy / self-grant | AttachUser/Role/GroupPolicy, PutUser/Role/GroupPolicy, CreatePolicyVersion, SetDefaultPolicyVersion, AddUserToGroup |
| B — Credential theft | CreateAccessKey, CreateLoginProfile, UpdateLoginProfile |
| C — Trust-policy manipulation | UpdateAssumeRolePolicy |
| D — PassRole-to-compute | Lambda, EC2, CloudFormation, Glue, DataPipeline, SageMaker, CodeBuild, ECS, UpdateFunctionCode |
| E — Role chaining | AssumeRole |

Adding a technique means writing one `@rule`-decorated function in `rules.py`.

## Testing

```bash
python3 make_fixtures.py   # (re)build the test fixtures
python3 evaluate.py        # run the evaluation
```

| Fixture | Precision | Recall | False positives | Rules exercised |
|---------|-----------|--------|-----------------|-----------------|
| vulnerable (25 planted chains) | 100% | 100% | 0 | 23 / 23 |
| clean baseline | 100% | 100% | 0 | 0 / 23 |

The clean baseline includes deliberate "near miss" identities (half a chain) to
guard against false positives.

Those numbers need a caveat. The fixtures were written alongside the rules, and
each planted chain is built from the trigger conditions of the rule meant to
catch it, so what the suite really shows is that every rule fires where it was
designed to fire. It cannot find a technique nobody thought of, and it does not
exercise the gaps listed under Limitations.

## Roadmap

- [ ] OIDC / federated-identity modeling (e.g. GitHub Actions web-identity
      federation) and trust-policy misconfiguration rules (wildcard `sub`/`aud`).
- [ ] Sandbox verification — attempt a subset of flagged paths in a live AWS
      account (`boto3`) to confirm real exploitability.
- [ ] Left-to-right layered graph layout.

## Limitations

Known gaps in the rules themselves:

- The family A self-grant rules only match when the permission is granted on
  `Resource: "*"`. A grant scoped to the AdministratorAccess policy ARN is a
  real escalation and is currently missed.
- Trust policies are matched by substring, so a role trusting `.../user/alan`
  also matches a user called `al` and produces an edge that does not exist.
- Only the shortest path to admin is reported per identity, so alternative
  routes through the same identity stay invisible.
- Group membership is not modeled. Groups carry policies, but nothing records
  which users belong to them; `AddUserToGroup` is the only rule that looks at
  groups at all.
- The account ID is hardcoded in `rules.py`, so input files have to use the same
  one or the ARN-matching rules stop firing.

Not modeled at all: `NotAction`/`NotResource`, IAM condition keys (outside the
planned OIDC rules), service control policies, and permission boundaries. These
are the target of the sandbox-verification stage.

## References

- Rhino Security Labs — *AWS IAM Privilege Escalation Methods*
- NCC Group / PMapper — principal-mapping edge definitions
- Pacu — AWS exploitation framework

## License

MIT (or as required by the course).
