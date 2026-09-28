"""
Build the test fixtures (proposal §8):

  fixtures/vulnerable.json  — one planted escalation chain per implemented rule,
                              plus benign identities. Each identity is tagged
                              "expect": true/false = should it reach admin?
  fixtures/clean.json       — no escalation paths, incl. "near miss" identities
                              that have half of a chain (to catch false positives).

Run:  python3 make_fixtures.py
"""

import json
import os

ACCT = "123456789012"


def allow(action, resource="*"):
    return {"Effect": "Allow", "Action": action, "Resource": resource}


def user(name, statements, expect):
    return {"name": name, "type": "user", "expect": expect,
            "policy": {"Statement": statements}}


def role(name, statements, trust, expect):
    return {"name": name, "type": "role", "expect": expect,
            "policy": {"Statement": statements}, "trust_policy": {"Statement": trust}}


def group(name, statements, expect):
    return {"name": name, "type": "group", "expect": expect,
            "policy": {"Statement": statements}}


def trust_service(svc):
    return [{"Effect": "Allow", "Principal": {"Service": svc}, "Action": "sts:AssumeRole"}]


def trust_principal(*arns):
    return [{"Effect": "Allow", "Principal": {"AWS": list(arns)}, "Action": "sts:AssumeRole"}]


ADMIN_STMT = [allow("*")]
ROLE = lambda n: f"arn:aws:iam::{ACCT}:role/{n}"
USER = lambda n: f"arn:aws:iam::{ACCT}:user/{n}"


def build_vulnerable():
    ids = []

    # --- admin target roles for the PassRole-to-compute family (all benign as
    #     SOURCES: they are already admin, so the analyzer never flags them) ---
    ids += [
        role("admin-role", ADMIN_STMT, trust_service("lambda.amazonaws.com"), expect=False),
        role("ec2-role",   ADMIN_STMT, trust_service("ec2.amazonaws.com"), expect=False),
        role("cfn-role",   ADMIN_STMT, trust_service("cloudformation.amazonaws.com"), expect=False),
        role("glue-role",  ADMIN_STMT, trust_service("glue.amazonaws.com"), expect=False),
        role("dp-role",    ADMIN_STMT, trust_service("datapipeline.amazonaws.com"), expect=False),
        role("sm-role",    ADMIN_STMT, trust_service("sagemaker.amazonaws.com"), expect=False),
        role("cb-role",    ADMIN_STMT, trust_service("codebuild.amazonaws.com"), expect=False),
        role("ecs-role",   ADMIN_STMT, trust_service("ecs-tasks.amazonaws.com"), expect=False),
        group("admins",    ADMIN_STMT, expect=False),
        user("bob", [allow("s3:GetObject")], expect=False),  # clean control
    ]

    # --- Family A: policy / self-grant (each reaches admin directly) ---
    ids += [
        user("attacher",       [allow("iam:AttachUserPolicy")], expect=True),
        user("group_attacher", [allow("iam:AttachGroupPolicy")], expect=True),
        user("put_user",       [allow("iam:PutUserPolicy")], expect=True),
        user("put_group",      [allow("iam:PutGroupPolicy")], expect=True),
        user("versioner",      [allow("iam:CreatePolicyVersion")], expect=True),
        user("defaulter",      [allow("iam:SetDefaultPolicyVersion")], expect=True),
        user("joiner",         [allow("iam:AddUserToGroup")], expect=True),
        # a ROLE that can self-attach admin (covers attach_role_policy) and is the
        # assume target for the role-chaining cases below
        role("deploy-role", [allow("iam:AttachRolePolicy")],
             trust_principal(USER("carol"), ROLE("stage-role")), expect=True),
        # a ROLE that can self-inline admin (covers put_role_policy)
        role("pr-role", [allow("iam:PutRolePolicy")], trust_service("ec2.amazonaws.com"), expect=True),
    ]

    # --- Family B: credential theft (victim = alice, who can reach admin) ---
    ids += [
        user("keythief",     [allow("iam:CreateAccessKey", USER("alice"))], expect=True),
        user("login_creator",[allow("iam:CreateLoginProfile", USER("alice"))], expect=True),
        user("login_updater",[allow("iam:UpdateLoginProfile", USER("alice"))], expect=True),
    ]

    # --- Family C: trust-policy manipulation ---
    ids += [
        user("trustmod", [allow("iam:UpdateAssumeRolePolicy", ROLE("admin-role"))], expect=True),
    ]

    # --- Family D: PassRole-to-compute (one attacker per service) ---
    ids += [
        user("alice",       [allow("lambda:CreateFunction"), allow("iam:PassRole", ROLE("admin-role"))], expect=True),
        user("ec2attacker", [allow("ec2:RunInstances"), allow("iam:PassRole", ROLE("ec2-role"))], expect=True),
        user("cfnattacker", [allow("cloudformation:CreateStack"), allow("iam:PassRole", ROLE("cfn-role"))], expect=True),
        user("glueattacker",[allow("glue:CreateDevEndpoint"), allow("iam:PassRole", ROLE("glue-role"))], expect=True),
        user("dpattacker",  [allow("datapipeline:CreatePipeline"), allow("iam:PassRole", ROLE("dp-role"))], expect=True),
        user("smattacker",  [allow("sagemaker:CreateNotebookInstance"), allow("iam:PassRole", ROLE("sm-role"))], expect=True),
        user("cbattacker",  [allow("codebuild:CreateProject"), allow("iam:PassRole", ROLE("cb-role"))], expect=True),
        user("ecsattacker", [allow("ecs:RegisterTaskDefinition"), allow("ecs:RunTask"), allow("iam:PassRole", ROLE("ecs-role"))], expect=True),
        user("codehijacker",[allow("lambda:UpdateFunctionCode")], expect=True),  # hijacks admin-role's Lambda
    ]

    # --- Family E: role chaining ---
    ids += [
        user("carol", [allow("sts:AssumeRole", ROLE("deploy-role"))], expect=True),
        user("dave",  [allow("sts:AssumeRole", ROLE("stage-role"))], expect=True),
        role("stage-role", [allow("sts:AssumeRole", ROLE("deploy-role"))],
             trust_principal(USER("dave")), expect=True),
    ]

    return {"account_id": ACCT, "identities": ids}


def build_clean():
    ids = [
        user("reader",   [allow("s3:GetObject"), allow("s3:ListBucket")], expect=False),
        user("watcher",  [allow("cloudwatch:GetMetricData"), allow("logs:GetLogEvents")], expect=False),
        # NEAR MISSES — half a chain, must NOT be flagged (false-positive test):
        user("half1", [allow("lambda:CreateFunction")], expect=False),               # create but no PassRole
        user("half2", [allow("iam:PassRole", ROLE("some-role"))], expect=False),      # PassRole but no create
        role("scoped-role", [allow("s3:GetObject")], trust_service("ec2.amazonaws.com"), expect=False),
    ]
    return {"account_id": ACCT, "identities": ids}


if __name__ == "__main__":
    os.makedirs("fixtures", exist_ok=True)
    for name, data in [("vulnerable", build_vulnerable()), ("clean", build_clean())]:
        path = f"fixtures/{name}.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        n = len(data["identities"])
        exp = sum(1 for i in data["identities"] if i.get("expect"))
        print(f"wrote {path}: {n} identities, {exp} expected escalations")
