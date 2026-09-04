# tenantaudit

Finds IAM roles that can read a multi-tenant DynamoDB table across tenants.

In a shared table every tenant's rows sit next to each other. IAM can restrict a
role to its own tenant's partition keys with `dynamodb:LeadingKeys`. This tool
lists the roles that can reach a table without that condition.

Work in progress.
