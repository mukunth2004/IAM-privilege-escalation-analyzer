"""
Step 3 — The Rule Engine (full rule set).

Each rule encodes ONE documented AWS IAM privilege-escalation technique. A rule
looks at a single identity and yields the control edges it can create:
(target, label) meaning "this identity can gain control of `target`, via `label`".

  target can be:
    * ADMIN            -> the technique lands you at full control directly
    * another identity -> you seize that identity/role, and the path search
                          continues from there (this is what finds long chains)

The techniques are grouped into five families:

  A. Policy / self-grant       — give yourself admin by editing IAM policies
  B. Credential theft          — mint credentials for a more privileged identity
  C. Trust-policy manipulation — rewrite a role's trust so you can assume it
  D. PassRole-to-compute       — run code as a role by handing it to a service
  E. Role chaining             — assume a role you're already trusted by

Primary reference: Rhino Security Labs, "AWS IAM Privilege Escalation Methods"
(the same technique catalogue PMapper and Pacu implement).

Adding a technique = writing one more @rule function. The families never touch.
"""

from parser import allows

ADMIN = "ADMIN"
ACCOUNT_ID = "123456789012"

_RULES = []


def rule(fn):
    """Register a function as an escalation rule."""
    _RULES.append(fn)
    return fn


def registered_rules():
    return [r.__name__ for r in _RULES]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def is_admin(identity):
    """Can this identity already do everything? (action '*' on resource '*')"""
    return allows(identity["statements"], "*", "*")


def _role_arn(name):
    return f"arn:aws:iam::{ACCOUNT_ID}:role/{name}"


def _user_arn(name):
    return f"arn:aws:iam::{ACCOUNT_ID}:user/{name}"


def _trust_allows_principal(role, principal_name):
    """Does the role's trust policy name this principal (so it can assume it)?"""
    for stmt in (role.get("trust_policy") or {}).get("Statement", []):
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        values = []
        if isinstance(principal, dict):
            for v in principal.values():
                values += v if isinstance(v, list) else [v]
        for v in values:
            if v == "*" or principal_name in v:
                return True
    return False


def _trust_allows_service(role, service):
    """Does the role's trust policy allow an AWS service (e.g. lambda) to use it?
    A PassRole-to-compute attack only works if the target service is allowed to
    assume the role."""
    for stmt in (role.get("trust_policy") or {}).get("Statement", []):
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        svc = principal.get("Service") if isinstance(principal, dict) else None
        svc = svc if isinstance(svc, list) else ([svc] if svc else [])
        if service in svc:
            return True
    return False


# =========================================================================== #
# Family A — Policy / self-grant techniques (all land at ADMIN)
# =========================================================================== #
@rule
def attach_user_policy(name, identity, identities):
    """iam:AttachUserPolicy -> attach AdministratorAccess to yourself."""
    if identity["type"] == "user" and allows(identity["statements"], "iam:AttachUserPolicy"):
        yield ADMIN, "iam:AttachUserPolicy (attach AdministratorAccess to self)"


@rule
def attach_role_policy(name, identity, identities):
    """iam:AttachRolePolicy -> attach AdministratorAccess to your role."""
    if identity["type"] == "role" and allows(identity["statements"], "iam:AttachRolePolicy"):
        yield ADMIN, "iam:AttachRolePolicy (attach AdministratorAccess to self)"


@rule
def attach_group_policy(name, identity, identities):
    """iam:AttachGroupPolicy -> attach admin to a group you belong to."""
    if allows(identity["statements"], "iam:AttachGroupPolicy"):
        yield ADMIN, "iam:AttachGroupPolicy (attach AdministratorAccess to own group)"


@rule
def put_user_policy(name, identity, identities):
    """iam:PutUserPolicy -> inline an admin policy onto yourself."""
    if identity["type"] == "user" and allows(identity["statements"], "iam:PutUserPolicy"):
        yield ADMIN, "iam:PutUserPolicy (write inline admin policy on self)"


@rule
def put_role_policy(name, identity, identities):
    """iam:PutRolePolicy -> inline an admin policy onto your role."""
    if identity["type"] == "role" and allows(identity["statements"], "iam:PutRolePolicy"):
        yield ADMIN, "iam:PutRolePolicy (write inline admin policy on self)"


@rule
def put_group_policy(name, identity, identities):
    """iam:PutGroupPolicy -> inline an admin policy onto your group."""
    if allows(identity["statements"], "iam:PutGroupPolicy"):
        yield ADMIN, "iam:PutGroupPolicy (write inline admin policy on own group)"


@rule
def create_policy_version(name, identity, identities):
    """iam:CreatePolicyVersion -> publish a new default version granting *:*."""
    if allows(identity["statements"], "iam:CreatePolicyVersion"):
        yield ADMIN, "iam:CreatePolicyVersion (rewrite an attached policy to full access)"


@rule
def set_default_policy_version(name, identity, identities):
    """iam:SetDefaultPolicyVersion -> roll a policy back to an over-permissive version."""
    if allows(identity["statements"], "iam:SetDefaultPolicyVersion"):
        yield ADMIN, "iam:SetDefaultPolicyVersion (activate an over-permissive policy version)"


@rule
def add_user_to_group(name, identity, identities):
    """iam:AddUserToGroup -> add yourself to a group that already has admin."""
    if identity["type"] != "user" or not allows(identity["statements"], "iam:AddUserToGroup"):
        return
    for gname, g in identities.items():
        if g["type"] == "group" and is_admin(g):
            yield ADMIN, f"iam:AddUserToGroup (join admin group '{gname}')"


# =========================================================================== #
# Family B — Credential theft (land on ANOTHER identity, then chain onward)
# =========================================================================== #
@rule
def create_access_key(name, identity, identities):
    """iam:CreateAccessKey on another user -> mint API keys and act as them."""
    for uname, u in identities.items():
        if u["type"] == "user" and uname != name \
                and allows(identity["statements"], "iam:CreateAccessKey", _user_arn(uname)):
            yield uname, f"iam:CreateAccessKey (mint API keys for {uname})"


@rule
def create_login_profile(name, identity, identities):
    """iam:CreateLoginProfile on another user -> set a console password and log in."""
    for uname, u in identities.items():
        if u["type"] == "user" and uname != name \
                and allows(identity["statements"], "iam:CreateLoginProfile", _user_arn(uname)):
            yield uname, f"iam:CreateLoginProfile (set console password for {uname})"


@rule
def update_login_profile(name, identity, identities):
    """iam:UpdateLoginProfile on another user -> reset their password and log in."""
    for uname, u in identities.items():
        if u["type"] == "user" and uname != name \
                and allows(identity["statements"], "iam:UpdateLoginProfile", _user_arn(uname)):
            yield uname, f"iam:UpdateLoginProfile (reset console password for {uname})"


# =========================================================================== #
# Family C — Trust-policy manipulation (land on a role)
# =========================================================================== #
@rule
def update_assume_role_policy(name, identity, identities):
    """iam:UpdateAssumeRolePolicy -> rewrite a role's trust policy to trust YOU,
    then assume it."""
    for rname, r in identities.items():
        if r["type"] == "role" and rname != name \
                and allows(identity["statements"], "iam:UpdateAssumeRolePolicy", _role_arn(rname)):
            yield rname, f"iam:UpdateAssumeRolePolicy (rewrite trust of {rname}, then assume it)"


# =========================================================================== #
# Family D — PassRole-to-compute (land on the role the service will run as)
# =========================================================================== #
_COMPUTE_SERVICES = [
    ("PassRoleToLambda",         ["lambda:CreateFunction"],                          "lambda.amazonaws.com"),
    ("PassRoleToEC2",            ["ec2:RunInstances"],                               "ec2.amazonaws.com"),
    ("PassRoleToCloudFormation", ["cloudformation:CreateStack"],                     "cloudformation.amazonaws.com"),
    ("PassRoleToGlue",           ["glue:CreateDevEndpoint"],                         "glue.amazonaws.com"),
    ("PassRoleToDataPipeline",   ["datapipeline:CreatePipeline"],                    "datapipeline.amazonaws.com"),
    ("PassRoleToSageMaker",      ["sagemaker:CreateNotebookInstance"],               "sagemaker.amazonaws.com"),
    ("PassRoleToCodeBuild",      ["codebuild:CreateProject"],                        "codebuild.amazonaws.com"),
    ("PassRoleToECS",            ["ecs:RegisterTaskDefinition", "ecs:RunTask"],      "ecs-tasks.amazonaws.com"),
]


def _make_passrole_rule(create_actions, service):
    short = service.split(".")[0]

    def r(name, identity, identities):
        if not all(allows(identity["statements"], a) for a in create_actions):
            return
        for rname, role in identities.items():
            if role["type"] != "role" or rname == name:
                continue
            if allows(identity["statements"], "iam:PassRole", _role_arn(rname)) \
                    and _trust_allows_service(role, service):
                yield rname, f"iam:PassRole + {'+'.join(create_actions)} (run as {rname} via {short})"
    return r


for _rule_name, _actions, _service in _COMPUTE_SERVICES:
    _fn = _make_passrole_rule(_actions, _service)
    _fn.__name__ = _rule_name
    rule(_fn)


@rule
def update_lambda_code(name, identity, identities):
    """lambda:UpdateFunctionCode -> overwrite the code of an existing Lambda so it
    runs your payload as that function's (privileged) execution role."""
    if not allows(identity["statements"], "lambda:UpdateFunctionCode"):
        return
    for rname, role in identities.items():
        if role["type"] == "role" and _trust_allows_service(role, "lambda.amazonaws.com"):
            yield rname, f"lambda:UpdateFunctionCode (hijack a Lambda running as {rname})"


# =========================================================================== #
# Family E — Role chaining
# =========================================================================== #
@rule
def assume_role(name, identity, identities):
    """sts:AssumeRole -> become a role that trusts you. The core multi-hop edge."""
    for rname, role in identities.items():
        if role["type"] != "role" or rname == name:
            continue
        if allows(identity["statements"], "sts:AssumeRole", _role_arn(rname)) \
                and _trust_allows_principal(role, name):
            yield rname, "sts:AssumeRole"
