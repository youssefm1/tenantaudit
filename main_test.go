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

func TestRunSeveralTables(t *testing.T) {
	code, stdout, stderr := runCLI(t,
		"--table", "arn:aws:dynamodb:us-east-1:111122223333:table/orders",
		"--table", "arn:aws:dynamodb:us-east-1:111122223333:table/users",
		"--file", "testdata/account.json", "--tenant-key-prefix", "org#")
	if code != exitFindings || stderr != "" {
		t.Errorf("code = %d, stderr = %q", code, stderr)
	}

	const golden = "testdata/orders-users.golden"
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

func TestRunSeveralTablesJSON(t *testing.T) {
	_, stdout, _ := runCLI(t, "--table", "orders", "--table", "users", "--region", "us-east-1",
		"--file", "testdata/account.json", "--format", "json")

	var out []struct {
		Table string `json:"table"`
		Roles []struct {
			Role string `json:"role"`
		} `json:"roles"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if len(out) != 2 || out[0].Table != "orders" || out[1].Table != "users" {
		t.Fatalf("tables = %+v", out)
	}
	// users-service-role only reaches the users table.
	for i, want := range []bool{false, true} {
		found := false
		for _, r := range out[i].Roles {
			found = found || r.Role == "users-service-role"
		}
		if found != want {
			t.Errorf("%s: users-service-role found = %v, want %v", out[i].Table, found, want)
		}
	}
}

func TestRunPrefixPerTable(t *testing.T) {
	const orders = "arn:aws:dynamodb:us-east-1:111122223333:table/orders"
	const off = "not to the"

	// The orders policy scopes to org# keys, so a user# prefix is noted.
	_, stdout, _ := runCLI(t, "--table", orders+"=user#", "--file", "testdata/scoped.json")
	if !strings.Contains(stdout, off+" user# prefix") {
		t.Errorf("own prefix not applied:\n%s", stdout)
	}

	// A table's own prefix wins over --tenant-key-prefix.
	_, stdout, _ = runCLI(t, "--table", orders+"=org#", "--tenant-key-prefix", "user#", "--file", "testdata/scoped.json")
	if strings.Contains(stdout, off) {
		t.Errorf("own prefix should win:\n%s", stdout)
	}

	// Tables without one fall back to --tenant-key-prefix.
	_, stdout, _ = runCLI(t, "--table", orders, "--tenant-key-prefix", "user#", "--file", "testdata/scoped.json")
	if !strings.Contains(stdout, off+" user# prefix") {
		t.Errorf("fallback prefix not applied:\n%s", stdout)
	}

	// An empty prefix turns the check off for that table.
	_, stdout, _ = runCLI(t, "--table", orders+"=", "--tenant-key-prefix", "user#", "--file", "testdata/scoped.json")
	if strings.Contains(stdout, off) || !strings.HasPrefix(stdout, "orders\n") {
		t.Errorf("empty prefix should disable the check:\n%s", stdout)
	}
}

func TestRunSeveralTablesExitCode(t *testing.T) {
	// One clean table does not hide findings on the other, whatever the order.
	clean := "arn:aws:dynamodb:us-east-1:111122223333:table/orders"
	for _, args := range [][]string{
		{"--table", clean, "--table", "users"},
		{"--table", "users", "--table", clean},
	} {
		args = append(args, "--file", "testdata/scoped.json")
		if code, stdout, _ := runCLI(t, args...); code != exitFindings {
			t.Errorf("%v: code = %d\n%s", args, code, stdout)
		}
	}
	if code, stdout, _ := runCLI(t, "--table", clean, "--file", "testdata/scoped.json"); code != exitOK {
		t.Errorf("clean table: code = %d\n%s", code, stdout)
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
		{"--table", "orders", "--table", "arn:aws:s3:::users", "--file", "testdata/account.json"},
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
