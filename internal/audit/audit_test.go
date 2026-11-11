package audit

import (
	"strings"
	"testing"

	"github.com/youssefm1/tenantaudit/internal/policy"
)

var orders = policy.Table{Name: "orders", Region: "us-east-1", Account: "111122223333"}

const ordersARN = "arn:aws:dynamodb:us-east-1:111122223333:table/orders"

func role(t *testing.T, docs ...string) Role {
	t.Helper()
	r := Role{Name: "test-role"}
	for i, d := range docs {
		doc, err := policy.Parse([]byte(d))
		if err != nil {
			t.Fatalf("policy %d: %v", i, err)
		}
		r.Policies = append(r.Policies, Policy{Name: "p" + string(rune('1'+i)), Document: doc})
	}
	return r
}

func TestCheckLevels(t *testing.T) {
	tests := []struct {
		name string
		docs []string
		want Level
	}{
		{
			name: "no dynamodb access",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`},
			want: NoAccess,
		},
		{
			name: "another table",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:*","Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/users"}]}`},
			want: NoAccess,
		},
		{
			name: "control plane only",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":["dynamodb:DescribeTable","dynamodb:ListTables"],"Resource":"*"}]}`},
			want: NoAccess,
		},
		{
			name: "scoped read",
			docs: []string{`{"Statement":[{
				"Effect":"Allow",
				"Action":["dynamodb:GetItem","dynamodb:Query"],
				"Resource":"` + ordersARN + `",
				"Condition":{"ForAllValues:StringEquals":{"dynamodb:LeadingKeys":["org#${aws:PrincipalTag/org}"]}}
			}]}`},
			want: Scoped,
		},
		{
			name: "query with no condition",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query","Resource":"` + ordersARN + `"}]}`},
			want: Unscoped,
		},
		{
			name: "leading keys set to star",
			docs: []string{`{"Statement":[{
				"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"` + ordersARN + `",
				"Condition":{"ForAllValues:StringLike":{"dynamodb:LeadingKeys":["*"]}}
			}]}`},
			want: Unscoped,
		},
		{
			name: "for any value",
			docs: []string{`{"Statement":[{
				"Effect":"Allow","Action":"dynamodb:BatchGetItem","Resource":"` + ordersARN + `",
				"Condition":{"ForAnyValue:StringEquals":{"dynamodb:LeadingKeys":["org#1"]}}
			}]}`},
			want: Unscoped,
		},
		{
			name: "scan",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"` + ordersARN + `"}]}`},
			want: ScanAll,
		},
		{
			name: "scan slips past leading keys",
			docs: []string{`{"Statement":[{
				"Effect":"Allow","Action":["dynamodb:Query","dynamodb:Scan"],"Resource":"` + ordersARN + `",
				"Condition":{"ForAllValues:StringEquals":{"dynamodb:LeadingKeys":["org#1"]}}
			}]}`},
			want: ScanAll,
		},
		{
			name: "null check stops scan",
			docs: []string{`{"Statement":[{
				"Effect":"Allow","Action":"dynamodb:*","Resource":"` + ordersARN + `",
				"Condition":{
					"ForAllValues:StringEquals":{"dynamodb:LeadingKeys":["org#1"]},
					"Null":{"dynamodb:LeadingKeys":"false"}
				}
			}]}`},
			want: Scoped,
		},
		{
			name: "admin wildcard",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
			want: ScanAll,
		},
		{
			name: "deny removes scan",
			docs: []string{
				`{"Statement":[{"Effect":"Allow","Action":["dynamodb:Query","dynamodb:Scan"],"Resource":"` + ordersARN + `"}]}`,
				`{"Statement":[{"Effect":"Deny","Action":"dynamodb:Scan","Resource":"*"}]}`,
			},
			want: Unscoped,
		},
		{
			name: "deny removes everything",
			docs: []string{
				`{"Statement":[{"Effect":"Allow","Action":"dynamodb:*","Resource":"*"}]}`,
				`{"Statement":[{"Effect":"Deny","Action":"dynamodb:*","Resource":["` + ordersARN + `","` + ordersARN + `/*"]}]}`,
			},
			want: NoAccess,
		},
		{
			name: "deny on the table leaves its stream",
			docs: []string{
				`{"Statement":[{"Effect":"Allow","Action":"dynamodb:*","Resource":"*"}]}`,
				`{"Statement":[{"Effect":"Deny","Action":"dynamodb:*","Resource":"` + ordersARN + `"}]}`,
			},
			want: ScanAll,
		},
		{
			name: "conditional deny is ignored",
			docs: []string{
				`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"*"}]}`,
				`{"Statement":[{"Effect":"Deny","Action":"dynamodb:Scan","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}]}`,
			},
			want: ScanAll,
		},
		{
			name: "one scoped and one unscoped policy",
			docs: []string{
				`{"Statement":[{
					"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"` + ordersARN + `",
					"Condition":{"ForAllValues:StringEquals":{"dynamodb:LeadingKeys":["org#1"]}}
				}]}`,
				`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query","Resource":"` + ordersARN + `"}]}`,
			},
			want: Unscoped,
		},
		{
			name: "index only",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query","Resource":"` + ordersARN + `/index/*"}]}`},
			want: Unscoped,
		},
		{
			name: "export",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:ExportTableToPointInTime","Resource":"` + ordersARN + `"}]}`},
			want: ScanAll,
		},
		{
			name: "export slips past leading keys",
			docs: []string{`{"Statement":[{
				"Effect":"Allow","Action":"dynamodb:ExportTableToPointInTime","Resource":"` + ordersARN + `",
				"Condition":{"ForAllValues:StringEquals":{"dynamodb:LeadingKeys":["org#1"]}}
			}]}`},
			want: ScanAll,
		},
		{
			name: "export on an index only",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:ExportTableToPointInTime","Resource":"` + ordersARN + `/index/*"}]}`},
			want: NoAccess,
		},
		{
			name: "deny removes export",
			docs: []string{
				`{"Statement":[{"Effect":"Allow","Action":["dynamodb:Query","dynamodb:ExportTableToPointInTime"],"Resource":"` + ordersARN + `"}]}`,
				`{"Statement":[{"Effect":"Deny","Action":"dynamodb:Export*","Resource":"*"}]}`,
			},
			want: Unscoped,
		},
		{
			name: "stream reader",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":["dynamodb:GetRecords","dynamodb:GetShardIterator"],"Resource":"` + ordersARN + `/stream/*"}]}`},
			want: ScanAll,
		},
		{
			name: "stream of another table",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:GetRecords","Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/users/stream/*"}]}`},
			want: NoAccess,
		},
		{
			name: "get records on the table arn is not a stream grant",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:GetRecords","Resource":"` + ordersARN + `"}]}`},
			want: NoAccess,
		},
		{
			name: "deny removes stream reads",
			docs: []string{
				`{"Statement":[{"Effect":"Allow","Action":"dynamodb:GetRecords","Resource":"*"}]}`,
				`{"Statement":[{"Effect":"Deny","Action":"dynamodb:GetRecords","Resource":"` + ordersARN + `/stream/*"}]}`,
			},
			want: NoAccess,
		},
		{
			name: "stream only grant gives no item access",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":["dynamodb:Query","dynamodb:Scan"],"Resource":"` + ordersARN + `/stream/*"}]}`},
			want: NoAccess,
		},
		{
			name: "query on a named index",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query","Resource":"` + ordersARN + `/index/by-status"}]}`},
			want: Unscoped,
		},
		{
			name: "scan on a named index",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"` + ordersARN + `/index/by-status"}]}`},
			want: ScanAll,
		},
		{
			name: "named index on another table",
			docs: []string{`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/users/index/by-status"}]}`},
			want: NoAccess,
		},
		{
			name: "deny on one index leaves the others",
			docs: []string{
				`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"` + ordersARN + `/index/*"}]}`,
				`{"Statement":[{"Effect":"Deny","Action":"dynamodb:Scan","Resource":"` + ordersARN + `/index/by-status"}]}`,
			},
			want: ScanAll,
		},
		{
			name: "deny on every index",
			docs: []string{
				`{"Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"` + ordersARN + `/index/by-status"}]}`,
				`{"Statement":[{"Effect":"Deny","Action":"dynamodb:Scan","Resource":"` + ordersARN + `/index/*"}]}`,
			},
			want: NoAccess,
		},
	}
	for _, tt := range tests {
		got := Check(role(t, tt.docs...), orders, Options{})
		if got.Level != tt.want {
			t.Errorf("%s: level = %v, want %v (grants %+v)", tt.name, got.Level, tt.want, got.Grants)
		}
	}
}

func TestCheckGrants(t *testing.T) {
	r := role(t, `{"Statement":[
		{"Sid":"Read","Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:Query"],"Resource":"`+ordersARN+`",
		 "Condition":{"ForAllValues:StringEquals":{"dynamodb:LeadingKeys":["org#${aws:PrincipalTag/org}"]}}},
		{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"`+ordersARN+`"}
	]}`)
	res := Check(r, orders, Options{})

	if len(res.Grants) != 2 {
		t.Fatalf("got %d grants, want 2: %+v", len(res.Grants), res.Grants)
	}
	worst, read := res.Grants[0], res.Grants[1]
	if worst.Level != ScanAll || worst.Statement != "statement 2" {
		t.Errorf("worst grant = %+v", worst)
	}
	if read.Level != Scoped || read.Statement != "Read" || strings.Join(read.Actions, ",") != "dynamodb:GetItem,dynamodb:Query" {
		t.Errorf("read grant = %+v", read)
	}
}

func TestCheckTenantPrefix(t *testing.T) {
	r := role(t, `{"Statement":[{
		"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"`+ordersARN+`",
		"Condition":{"ForAllValues:StringEquals":{"dynamodb:LeadingKeys":["user#${aws:userid}"]}}
	}]}`)

	res := Check(r, orders, Options{TenantKeyPrefix: "org#"})
	if res.Level != Scoped || !strings.Contains(res.Grants[0].Note, "not to the org# prefix") {
		t.Errorf("got %+v", res)
	}

	res = Check(r, orders, Options{TenantKeyPrefix: "user#"})
	if res.Grants[0].Note != "scoped by LeadingKeys" {
		t.Errorf("note = %q", res.Grants[0].Note)
	}
}

func TestCheckWildcardAfterPrefix(t *testing.T) {
	stmt := func(op, pattern string) string {
		return `{"Statement":[{
			"Effect":"Allow","Action":"dynamodb:Query","Resource":"` + ordersARN + `",
			"Condition":{"ForAllValues:` + op + `":{"dynamodb:LeadingKeys":["` + pattern + `"]}}
		}]}`
	}
	opts := Options{TenantKeyPrefix: "org#"}

	res := Check(role(t, stmt("StringLike", "org#*")), orders, opts)
	if res.Level != Unscoped || res.Grants[0].Note != "LeadingKeys wildcard matches every org# key" {
		t.Errorf("org#* = %+v", res)
	}

	for _, pattern := range []string{"org#42#*", "org#${aws:PrincipalTag/org}#*"} {
		if res := Check(role(t, stmt("StringLike", pattern)), orders, opts); res.Level != Scoped {
			t.Errorf("%s: level = %v, want scoped", pattern, res.Level)
		}
	}

	if res := Check(role(t, stmt("StringEquals", "org#*")), orders, opts); res.Level != Scoped {
		t.Errorf("StringEquals org#*: level = %v, want scoped", res.Level)
	}
}
