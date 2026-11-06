# tenantaudit

Finds IAM roles that can read or write a multi-tenant DynamoDB table across tenants.

In a shared table every tenant's items sit next to each other, usually under a
partition key like `org#42`. IAM can limit a role to its own tenant's keys with
the `dynamodb:LeadingKeys` condition. If a role is missing that condition, one
bug in the code using it can return another tenant's data.

`tenantaudit` reads every role in an account and tells you which ones can reach
a table without that guard.

```
$ tenantaudit --table arn:aws:dynamodb:us-east-1:111122223333:table/orders \
    --tenant-key-prefix "org#" --file testdata/account.json
orders
  ✗ admin-tools-role    scan      Scan                                   Scan reads every tenant                                  (admin, statement 1)
  ✗ legacy-sync-role    scan      Scan                                   Scan is not limited by LeadingKeys without a Null check  (sync, LooksScoped)
  ✗ report-export-role  unscoped  BatchGetItem, Query                    no tenant condition                                      (export, statement 1)
  ✓ api-read-role       scoped    GetItem, Query                         scoped by LeadingKeys                                    (orders-tenant-read, TenantRead)
  ✓ api-write-role      scoped    GetItem, BatchGetItem, Query +10 more  scoped by LeadingKeys                                    (tenant-write, TenantWrite)

3 of 5 roles with access can reach other tenants' items
```

## Install

```
go install github.com/youssefm1/tenantaudit@latest
```

## Usage

Against an AWS account, using your default credentials:

```
tenantaudit --table orders
tenantaudit --table arn:aws:dynamodb:us-east-1:111122223333:table/orders
```

It needs `iam:GetAccountAuthorizationDetails`, `iam:GetPolicy`,
`iam:GetPolicyVersion` and `sts:GetCallerIdentity`. It only reads.

Against a saved export, with no AWS access at all:

```
aws iam get-account-authorization-details > account.json
tenantaudit --table orders --file account.json
```

There is a sample export in `testdata/account.json` if you want to try it.

| Flag | What it does |
|---|---|
| `--table` | Table name or ARN. Required. |
| `--tenant-key-prefix` | Start of every tenant partition key, e.g. `org#`. Flags `LeadingKeys` wildcards like `org#*` that match every tenant, and notes any pattern that doesn't use the prefix. |
| `--file` | Read roles from a saved export instead of calling AWS. |
| `--region`, `--account` | Where the table lives, so policy ARNs for other regions or accounts are not matched. Filled in from your AWS config when left out. |
| `--format` | `text` or `json`. |

Exit code is `0` when every role with access is scoped, `1` when at least one
is not, and `2` when the audit could not run. That makes it usable as a CI check.

## How a role is graded

| Level | Meaning |
|---|---|
| `scan` | The role can `Scan`. A scan returns every tenant's items. |
| `unscoped` | The role can use key-based actions like `Query` or `GetItem` with no `LeadingKeys` condition, a condition that allows `*` or every key under the tenant prefix, or one that uses `ForAnyValue`. |
| `scoped` | Every statement that grants access is limited by `LeadingKeys`. |

A role gets its worst level. Roles with no item access to the table are left out.

One case is easy to miss. `ForAllValues` conditions pass when the key is absent
from the request, and `Scan` never sends a partition key. So a statement that
allows `Scan` under a `LeadingKeys` condition still allows a full scan, unless it
also has `"Null": {"dynamodb:LeadingKeys": "false"}`. This is flagged as `scan`.

## Limits

This reads identity policies on roles. It does not evaluate:

- permission boundaries, session policies, SCPs or resource-based policies
- `Deny` statements that have conditions (they are ignored, so the result can be stricter than reality)
- IAM users and groups
- PartiQL statements that run as full scans
- `dynamodb:Attributes` and other fine-grained conditions

It also can't see tenant checks done in application code. If your services
share one role and filter by tenant in code, every role will show as unscoped.
That is accurate from IAM's point of view, but it is not news to you.

Service-linked roles are skipped.
