package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/youssefm1/tenantaudit/internal/audit"
)

func sample() Report {
	return New("orders", []audit.Result{
		{Role: "idle-role"},
		{Role: "api-read-role", Level: audit.Scoped, Grants: []audit.Grant{
			{Policy: "tenant-read", Statement: "Read", Level: audit.Scoped, Actions: []string{"dynamodb:GetItem", "dynamodb:Query"}, Note: "scoped by LeadingKeys"},
		}},
		{Role: "admin-tools-role", Level: audit.ScanAll, Grants: []audit.Grant{
			{Policy: "admin", Statement: "statement 1", Level: audit.ScanAll, Actions: []string{"dynamodb:Scan"}, Note: "Scan reads every tenant"},
			{Policy: "admin", Statement: "statement 1", Level: audit.Unscoped, Actions: []string{"dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:PutItem"}, Note: "no tenant condition"},
		}},
		{Role: "export-role", Level: audit.Unscoped, Grants: []audit.Grant{
			{Policy: "export", Statement: "statement 1", Level: audit.Unscoped, Actions: []string{"dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:PutItem"}, Note: "no tenant condition"},
		}},
	}, []string{"role x: managed policy y was not checked"})
}

func TestText(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().Text(&buf); err != nil {
		t.Fatal(err)
	}
	want := `orders
  ✗ admin-tools-role  scan      Scan                                    Scan reads every tenant  (admin, statement 1)
  ✗ export-role       unscoped  GetItem, BatchGetItem, Query +1 more    no tenant condition      (export, statement 1)
  ✓ api-read-role     scoped    GetItem, Query                          scoped by LeadingKeys    (tenant-read, Read)

2 of 3 roles with access can reach other tenants' items
`
	if got := buf.String(); normalize(got) != normalize(want) {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// normalize collapses column padding so the test doesn't pin exact widths.
func normalize(s string) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		lines = append(lines, strings.Join(strings.Fields(line), " "))
	}
	return strings.Join(lines, "\n")
}

func TestTextNoAccess(t *testing.T) {
	var buf bytes.Buffer
	New("orders", []audit.Result{{Role: "idle-role"}}, nil).Text(&buf)
	if !strings.Contains(buf.String(), "no roles can read or write items (1 checked)") {
		t.Errorf("got %q", buf.String())
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().JSON(&buf); err != nil {
		t.Fatal(err)
	}
	var out jsonReport
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Summary != (jsonSummary{RolesChecked: 4, WithAccess: 3, CrossTenant: 2}) {
		t.Errorf("summary = %+v", out.Summary)
	}
	if out.Roles[0].Role != "admin-tools-role" || len(out.Roles[0].Grants) != 2 {
		t.Errorf("first role = %+v", out.Roles[0])
	}
	if len(out.Warnings) != 1 {
		t.Errorf("warnings = %v", out.Warnings)
	}
}

func TestJSONEmptyListsAreNotNull(t *testing.T) {
	var buf bytes.Buffer
	New("orders", nil, nil).JSON(&buf)
	if strings.Contains(buf.String(), "null") {
		t.Errorf("empty report should use [] not null:\n%s", buf.String())
	}
}

func TestJSONAll(t *testing.T) {
	var buf bytes.Buffer
	reports := []Report{sample(), New("users", nil, nil)}
	if err := JSONAll(&buf, reports); err != nil {
		t.Fatal(err)
	}
	var out []jsonReport
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].Table != "orders" || out[1].Table != "users" {
		t.Fatalf("got %+v", out)
	}
	if out[0].Summary.CrossTenant != 2 || len(out[1].Roles) != 0 {
		t.Errorf("got %+v", out)
	}
}
