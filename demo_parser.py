import json
from pathlib import Path
from parser import parse, allows

POLICY_FILE = Path(__file__).resolve().parent / "alice_policy.json"

with open(POLICY_FILE) as f:
    document = json.load(f)

statements = parse(document)

print(f"Parsed {len(statements)} statements:")
for s in statements:
    print(f"  {s.effect:5} {s.actions} on {s.resources}")

print("\nQuestions we can now answer:")

# Can Alice create a Lambda?  (Action given as a list in the policy)
print("  create a lambda?            ",
      allows(statements, "lambda:CreateFunction"))

# Can Alice pass the 'admin' role?  (this is the dangerous half of the chain)
print("  pass the admin-role?        ",
      allows(statements, "iam:PassRole", "arn:aws:iam::123456789012:role/admin-role"))

# Can Alice pass some 'other' role?  (if resource doesn't match then 'False')
print("  pass a different role?      ",
      allows(statements, "iam:PassRole", "arn:aws:iam::123456789012:role/backup-role"))

# Deny override: even with no 'Allow' for DeleteRole the explicit Deny blocks it
print("  delete a role? (Deny wins)  ",
      allows(statements, "iam:DeleteRole", "arn:aws:iam::123456789012:role/admin-role"))

# Something never granted at all means default deny
print("  read an S3 bucket?          ",
      allows(statements, "s3:GetObject"))

# NotAction means everything except the listed actions
power_user = parse({"Statement": [
    {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
]})

print("\nPower-user policy (allow everything except iam:*):")
print("  launch an EC2 instance?     ", allows(power_user, "ec2:RunInstances"))
print("  attach a policy? (excluded) ", allows(power_user, "iam:AttachUserPolicy"))
print("  can do everything?          ", allows(power_user, "*", "*"))
