// Command tenantaudit lists the IAM roles that can reach a multi-tenant
// DynamoDB table and says whether each one is limited to its own tenant.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/youssefm1/tenantaudit/internal/audit"
	"github.com/youssefm1/tenantaudit/internal/policy"
	"github.com/youssefm1/tenantaudit/internal/report"
	"github.com/youssefm1/tenantaudit/internal/source"
)

// Exit codes.
const (
	exitOK       = 0 // every role with access is scoped
	exitFindings = 1 // at least one role can reach other tenants
	exitError    = 2 // bad usage or the audit could not run
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tenantaudit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tableFlag := fs.String("table", "", "table name or ARN (required)")
	prefix := fs.String("tenant-key-prefix", "", "start of every tenant partition key, e.g. org#")
	file := fs.String("file", "", "read roles from a `path` saved with aws iam get-account-authorization-details, instead of calling AWS")
	region := fs.String("region", "", "table region, used to match policy ARNs")
	account := fs.String("account", "", "table account ID, used to match policy ARNs")
	format := fs.String("format", "text", "output format: text or json")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tenantaudit --table <name|arn> [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *tableFlag == "" || fs.NArg() > 0 {
		fs.Usage()
		return exitError
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "unknown format %q\n", *format)
		return exitError
	}

	table, err := parseTable(*tableFlag)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if *region != "" {
		table.Region = *region
	}
	if *account != "" {
		table.Account = *account
	}

	var acct *source.Account
	if *file != "" {
		acct, err = source.FromFile(*file)
	} else {
		acct, err = fromAWS(ctx, &table, stderr)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}

	results := make([]audit.Result, 0, len(acct.Roles))
	for _, role := range acct.Roles {
		results = append(results, audit.Check(role, table, audit.Options{TenantKeyPrefix: *prefix}))
	}
	rep := report.New(table.Name, results, acct.Warnings)

	for _, w := range acct.Warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	if *format == "json" {
		err = rep.JSON(stdout)
	} else {
		err = rep.Text(stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if rep.CrossTenant() > 0 {
		return exitFindings
	}
	return exitOK
}

// parseTable accepts "orders" or a full table ARN.
func parseTable(s string) (policy.Table, error) {
	if !strings.HasPrefix(s, "arn:") {
		return policy.Table{Name: s}, nil
	}
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 || parts[2] != "dynamodb" || !strings.HasPrefix(parts[5], "table/") {
		return policy.Table{}, fmt.Errorf("%q is not a DynamoDB table ARN", s)
	}
	name := strings.TrimPrefix(parts[5], "table/")
	if name == "" || strings.Contains(name, "/") {
		return policy.Table{}, fmt.Errorf("%q is not a DynamoDB table ARN", s)
	}
	return policy.Table{Name: name, Region: parts[3], Account: parts[4]}, nil
}

// fromAWS loads roles with the default credentials and fills in the table's
// region and account when the flags left them out.
func fromAWS(ctx context.Context, table *policy.Table, stderr io.Writer) (*source.Account, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if table.Region == "" {
		table.Region = cfg.Region
	}
	if cfg.Region == "" {
		// IAM is global but the client still needs a region to sign with.
		cfg.Region = "us-east-1"
	}
	if table.Account == "" {
		id, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			fmt.Fprintln(stderr, "warning: could not look up the account ID, matching any account:", err)
		} else {
			table.Account = aws.ToString(id.Account)
		}
	}
	return source.FromAWS(ctx, iam.NewFromConfig(cfg))
}
