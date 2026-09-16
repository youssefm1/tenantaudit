package source

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFromFile(t *testing.T) {
	acct, err := FromFile("testdata/account.json")
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, r := range acct.Roles {
		names = append(names, r.Name)
	}
	if got, want := strings.Join(names, ","), "admin-tools-role,api-read-role,report-export-role"; got != want {
		t.Fatalf("roles = %s, want %s (service-linked role skipped, sorted by name)", got, want)
	}

	admin, api := acct.Roles[0], acct.Roles[1]
	if len(admin.Policies) != 1 || admin.Policies[0].Document.Statement[0].Action[0] != "dynamodb:Scan" {
		t.Errorf("url-encoded inline policy not parsed: %+v", admin.Policies)
	}
	if len(api.Policies) != 1 || api.Policies[0].Document.Statement[0].Sid != "TenantRead" {
		t.Errorf("want the default version of the managed policy, got %+v", api.Policies)
	}

	if len(acct.Warnings) != 1 || !strings.Contains(acct.Warnings[0], "ReadOnlyAccess was not checked") {
		t.Errorf("warnings = %v", acct.Warnings)
	}
}

func TestBuildFetchesMissingPolicies(t *testing.T) {
	d := details{RoleDetailList: []roleDetail{
		{RoleName: "a", AttachedManagedPolicies: []attachedPolicy{{PolicyName: "shared", PolicyArn: "arn:shared"}}},
		{RoleName: "b", AttachedManagedPolicies: []attachedPolicy{{PolicyName: "shared", PolicyArn: "arn:shared"}}},
		{RoleName: "c", AttachedManagedPolicies: []attachedPolicy{{PolicyName: "broken", PolicyArn: "arn:broken"}}},
	}}
	calls := 0
	acct := build(d, func(arn string) ([]byte, error) {
		calls++
		if arn == "arn:broken" {
			return nil, errors.New("access denied")
		}
		return []byte(`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"*"}]}`), nil
	})

	if calls != 2 {
		t.Errorf("fetch called %d times, want 2 (shared policy fetched once)", calls)
	}
	if len(acct.Roles[0].Policies) != 1 || len(acct.Roles[1].Policies) != 1 {
		t.Errorf("fetched policy missing from roles a and b")
	}
	if len(acct.Roles[2].Policies) != 0 || len(acct.Warnings) != 2 {
		t.Errorf("role c should have no policies and two warnings, got %v", acct.Warnings)
	}
}

func TestFromFileErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"Users": []}`), 0o600)

	if _, err := FromFile(bad); err == nil {
		t.Error("want an error for a file with no roles")
	}
	if _, err := FromFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("want an error for a missing file")
	}
}
