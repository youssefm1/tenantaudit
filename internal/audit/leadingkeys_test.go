package audit

import (
	"reflect"
	"testing"

	"github.com/youssefm1/tenantaudit/internal/policy"
)

func conds(t *testing.T, json string) policy.Conditions {
	t.Helper()
	doc, err := policy.Parse([]byte(`{"Statement":{"Effect":"Allow","Condition":` + json + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	return doc.Statement[0].Condition
}

func TestLeadingKeys(t *testing.T) {
	tests := []struct {
		name string
		json string
		want keyScope
	}{
		{
			name: "no conditions",
			json: `{}`,
			want: keyScope{},
		},
		{
			name: "unrelated condition",
			json: `{"StringEquals": {"aws:PrincipalTag/team": "billing"}}`,
			want: keyScope{},
		},
		{
			name: "for all values",
			json: `{"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["org#${aws:PrincipalTag/org}"]}}`,
			want: keyScope{present: true, patterns: []string{"org#${aws:PrincipalTag/org}"}},
		},
		{
			name: "string like, mixed case key and operator",
			json: `{"forallvalues:stringlike": {"DynamoDB:leadingKeys": "org#42#*"}}`,
			want: keyScope{present: true, patterns: []string{"org#42#*"}},
		},
		{
			name: "with null check",
			json: `{
				"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["org#42"]},
				"Null": {"dynamodb:LeadingKeys": "false"}
			}`,
			want: keyScope{present: true, patterns: []string{"org#42"}, requiresKey: true},
		},
		{
			name: "null check true does not require a key",
			json: `{"Null": {"dynamodb:LeadingKeys": "true"}}`,
			want: keyScope{},
		},
		{
			name: "for any value",
			json: `{"ForAnyValue:StringEquals": {"dynamodb:LeadingKeys": ["org#42"]}}`,
			want: keyScope{present: true, anyValue: true, patterns: []string{"org#42"}},
		},
		{
			name: "negated operator is not a scope",
			json: `{"ForAllValues:StringNotEquals": {"dynamodb:LeadingKeys": ["org#42"]}}`,
			want: keyScope{},
		},
		{
			name: "if exists suffix",
			json: `{"ForAllValues:StringEqualsIfExists": {"dynamodb:LeadingKeys": ["org#42"]}}`,
			want: keyScope{present: true, patterns: []string{"org#42"}},
		},
	}
	for _, tt := range tests {
		got := leadingKeys(conds(t, tt.json))
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tt.name, got, tt.want)
		}
	}
}

func TestMatchesEverything(t *testing.T) {
	if !(keyScope{patterns: []string{"org#1", "*"}}).matchesEverything() {
		t.Error("a bare * should match everything")
	}
	if (keyScope{patterns: []string{"org#*"}}).matchesEverything() {
		t.Error("org#* is still limited to a prefix")
	}
}

func TestUsesPrefix(t *testing.T) {
	k := keyScope{patterns: []string{"org#${aws:PrincipalTag/org}", "org#shared"}}
	if !k.usesPrefix("org#") {
		t.Error("want prefix match")
	}
	if k.usesPrefix("tenant#") {
		t.Error("want prefix mismatch")
	}
}
