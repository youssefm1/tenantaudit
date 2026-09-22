package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRunGolden(t *testing.T) {
	const arn = "arn:aws:dynamodb:us-east-1:111122223333:table/orders"
	code, stdout, stderr := runCLI(t, "--table", arn, "--file", "testdata/account.json", "--tenant-key-prefix", "org#")

	if code != exitFindings {
		t.Errorf("exit code = %d, want %d", code, exitFindings)
	}
	if stderr != "" {
		t.Errorf("unexpected stderr: %s", stderr)
	}

	const golden = "testdata/orders.golden"
	if *update {
		if err := os.WriteFile(golden, []byte(stdout), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(want) {
		t.Errorf("output changed, rerun with -update if intended\ngot:\n%s\nwant:\n%s", stdout, want)
	}
}

func TestRunLevels(t *testing.T) {
	_, stdout, _ := runCLI(t, "--table", "arn:aws:dynamodb:us-east-1:111122223333:table/orders",
		"--file", "testdata/account.json", "--format", "json")

	var out struct {
		Summary struct {
			RolesChecked int `json:"roles_checked"`
		} `json:"summary"`
		Roles []struct {
			Role  string `json:"role"`
			Level string `json:"level"`
		} `json:"roles"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, r := range out.Roles {
		got[r.Role] = r.Level
	}
	want := map[string]string{
		"admin-tools-role":   "scan",     // Action * on Resource *
		"legacy-sync-role":   "scan",     // has LeadingKeys but no Null check, so Scan gets through
		"report-export-role": "unscoped", // Query with no condition
		"api-read-role":      "scoped",
		"api-write-role":     "scoped", // dynamodb:* is fine once the Null check blocks Scan
		// support-role is denied on the table, users-service-role is on
		// another table and eu-replica-role is in another region.
	}
	if out.Summary.RolesChecked != 8 {
		t.Errorf("roles checked = %d, want 8", out.Summary.RolesChecked)
	}
	if len(got) != len(want) {
		t.Errorf("roles with access = %v, want %v", got, want)
	}
	for role, level := range want {
		if got[role] != level {
			t.Errorf("%s = %q, want %q", role, got[role], level)
		}
	}
}

func TestRunTableNameMatchesAnyRegion(t *testing.T) {
	// With only a name there is no region to compare, so the eu-west-1
	// grant counts too.
	_, stdout, _ := runCLI(t, "--table", "orders", "--file", "testdata/account.json")
	if !strings.Contains(stdout, "eu-replica-role") {
		t.Errorf("eu-replica-role missing:\n%s", stdout)
	}

	_, stdout, _ = runCLI(t, "--table", "orders", "--region", "us-east-1", "--file", "testdata/account.json")
	if strings.Contains(stdout, "eu-replica-role") {
		t.Errorf("eu-replica-role should be filtered by --region:\n%s", stdout)
	}
}

func TestRunCleanTable(t *testing.T) {
	code, stdout, _ := runCLI(t, "--table", "invoices", "--region", "us-east-1", "--account", "111122223333", "--file", "testdata/account.json")
	// admin-tools-role and support-role still reach it through wildcards.
	if code != exitFindings || !strings.Contains(stdout, "admin-tools-role") || !strings.Contains(stdout, "support-role") {
		t.Errorf("code %d\n%s", code, stdout)
	}

	code, stdout, _ = runCLI(t, "--table", "arn:aws:dynamodb:us-east-1:999999999999:table/orders", "--file", "testdata/account.json")
	if code != exitFindings || strings.Contains(stdout, "api-read-role") {
		t.Errorf("only wildcard grants should match another account, code %d\n%s", code, stdout)
	}
}

func TestRunUsageErrors(t *testing.T) {
	tests := [][]string{
		{},
		{"--table", "orders", "--format", "xml", "--file", "testdata/account.json"},
		{"--table", "arn:aws:s3:::orders", "--file", "testdata/account.json"},
		{"--table", "orders", "--file", "testdata/missing.json"},
		{"--table", "orders", "extra", "--file", "testdata/account.json"},
		{"--nope"},
	}
	for _, args := range tests {
		if code, _, stderr := runCLI(t, args...); code != exitError || stderr == "" {
			t.Errorf("%v: code = %d, stderr = %q", args, code, stderr)
		}
	}
}

func TestParseTable(t *testing.T) {
	got, err := parseTable("arn:aws:dynamodb:us-east-1:111122223333:table/orders")
	if err != nil || got.Name != "orders" || got.Region != "us-east-1" || got.Account != "111122223333" {
		t.Errorf("got %+v, %v", got, err)
	}
	for _, bad := range []string{
		"arn:aws:dynamodb:us-east-1:111122223333:table/orders/index/by-date",
		"arn:aws:dynamodb:us-east-1:111122223333:table/",
		"arn:aws:dynamodb:us-east-1",
	} {
		if _, err := parseTable(bad); err == nil {
			t.Errorf("parseTable(%q) should fail", bad)
		}
	}
}
