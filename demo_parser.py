"""Quick demo: load Alice's policy and ask allows() some questions."""

import json
from parser import parse, allows

document = json.loads(open("alice_policy.json").read())
statements = parse(document)

print(f"Parsed {len(statements)} statements:")
for s in statements:
    print(f"  {s.effect:5} {s.actions} on {s.resources}")

print("\nQuestions we can now answer:")

# Can Alice create a Lambda?  (Action given as a list in the policy)
print("  create a lambda?            ",
      allows(statements, "lambda:CreateFunction"))

# Can Alice pass the ADMIN role?  (this is the dangerous half of the chain)
print("  pass the admin-role?        ",
      allows(statements, "iam:PassRole", "arn:aws:iam::123456789012:role/admin-role"))

# Can Alice pass some OTHER role?  (resource doesn't match -> False)
print("  pass a different role?      ",
      allows(statements, "iam:PassRole", "arn:aws:iam::123456789012:role/backup-role"))

# Deny override: even with no Allow for DeleteRole, the explicit Deny blocks it.
print("  delete a role? (Deny wins)  ",
      allows(statements, "iam:DeleteRole", "arn:aws:iam::123456789012:role/admin-role"))

# Something never granted at all -> default deny.
print("  read an S3 bucket?          ",
      allows(statements, "s3:GetObject"))
