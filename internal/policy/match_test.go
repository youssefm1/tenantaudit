package policy

import "testing"

func TestGlob(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"dynamodb:*", "dynamodb:query", true},
		{"dynamodb:get*", "dynamodb:getitem", true},
		{"dynamodb:get*", "dynamodb:query", false},
		{"table/orders", "table/orders", true},
		{"table/orders", "table/orders-archive", false},
		{"table/orders*", "table/orders-archive", true},
		{"table/*/index/*", "table/orders/index/by-date", true},
		{"table/ord?rs", "table/orders", true},
		{"table/ord?rs", "table/ordrs", false},
		{"*orders*", "table/orders/index/x", true},
		{"a*b*c", "aXbXbXc", true},
		{"a*b*c", "aXbXb", false},
	}
	for _, tt := range tests {
		if got := Glob(tt.pattern, tt.s); got != tt.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

func TestMatchesAction(t *testing.T) {
	tests := []struct {
		name   string
		st     Statement
		action string
		want   bool
	}{
		{"exact", Statement{Action: Strings{"dynamodb:Query"}}, "dynamodb:Query", true},
		{"case insensitive", Statement{Action: Strings{"DynamoDB:query"}}, "dynamodb:Query", true},
		{"service wildcard", Statement{Action: Strings{"dynamodb:*"}}, "dynamodb:Scan", true},
		{"everything", Statement{Action: Strings{"*"}}, "dynamodb:Scan", true},
		{"other service", Statement{Action: Strings{"s3:*"}}, "dynamodb:Scan", false},
		{"not action excludes", Statement{NotAction: Strings{"dynamodb:Scan"}}, "dynamodb:Scan", false},
		{"not action allows the rest", Statement{NotAction: Strings{"dynamodb:Scan"}}, "dynamodb:Query", true},
		{"no actions", Statement{}, "dynamodb:Query", false},
	}
	for _, tt := range tests {
		if got := tt.st.MatchesAction(tt.action); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestMatchesTable(t *testing.T) {
	full := Table{Name: "orders", Region: "us-east-1", Account: "111122223333"}
	nameOnly := Table{Name: "orders"}

	tests := []struct {
		name     string
		resource string
		table    Table
		want     bool
	}{
		{"star", "*", full, true},
		{"exact arn", "arn:aws:dynamodb:us-east-1:111122223333:table/orders", full, true},
		{"other table", "arn:aws:dynamodb:us-east-1:111122223333:table/users", full, false},
		{"other region", "arn:aws:dynamodb:eu-west-1:111122223333:table/orders", full, false},
		{"other account", "arn:aws:dynamodb:us-east-1:999999999999:table/orders", full, false},
		{"any region and account", "arn:aws:dynamodb:*:*:table/orders", full, true},
		{"all tables", "arn:aws:dynamodb:us-east-1:111122223333:table/*", full, true},
		{"short wildcard arn", "arn:aws:dynamodb:*", full, true},
		{"other service", "arn:aws:s3:::orders", full, false},
		{"index only", "arn:aws:dynamodb:us-east-1:111122223333:table/orders/index/*", full, false},
		{"unknown region still matches", "arn:aws:dynamodb:eu-west-1:999999999999:table/orders", nameOnly, true},
		{"policy variable in arn", "arn:aws:dynamodb:us-east-1:${aws:PrincipalAccount}:table/orders", full, true},
		{"not an arn", "orders", full, false},
	}
	for _, tt := range tests {
		st := Statement{Resource: Strings{tt.resource}}
		if got := st.MatchesTable(tt.table); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestMatchesIndex(t *testing.T) {
	table := Table{Name: "orders"}
	tests := []struct {
		resource   string
		any, every bool
	}{
		{"arn:aws:dynamodb:*:*:table/orders/index/*", true, true},
		{"arn:aws:dynamodb:*:*:table/orders/*", true, true},
		{"arn:aws:dynamodb:*:*:table/orders", false, false},
		{"arn:aws:dynamodb:*:*:table/*", true, true},
		{"*", true, true},
		{"arn:aws:dynamodb:*:*:table/orders/index/by-status", true, false},
		{"arn:aws:dynamodb:*:*:table/orders/index/by-*", true, false},
		{"arn:aws:dynamodb:*:*:table/*/index/by-status", true, false},
		{"arn:aws:dynamodb:*:*:table/users/index/by-status", false, false},
		{"arn:aws:dynamodb:*:*:table/orders-archive/index/by-status", false, false},
	}
	for _, tt := range tests {
		st := Statement{Resource: Strings{tt.resource}}
		if got := st.MatchesIndex(table); got != tt.any {
			t.Errorf("MatchesIndex(%q) = %v, want %v", tt.resource, got, tt.any)
		}
		if got := st.MatchesEveryIndex(table); got != tt.every {
			t.Errorf("MatchesEveryIndex(%q) = %v, want %v", tt.resource, got, tt.every)
		}
	}
}

func TestMatchesIndexNotResource(t *testing.T) {
	table := Table{Name: "orders"}
	// Leaving out one index still covers the others.
	one := Statement{NotResource: Strings{"arn:aws:dynamodb:*:*:table/orders/index/by-status"}}
	if !one.MatchesIndex(table) {
		t.Error("NotResource on one index should still cover the rest")
	}
	all := Statement{NotResource: Strings{"arn:aws:dynamodb:*:*:table/orders/index/*"}}
	if all.MatchesIndex(table) {
		t.Error("NotResource on every index should cover none")
	}
}

func TestMatchesStream(t *testing.T) {
	table := Table{Name: "orders"}
	tests := []struct {
		resource   string
		any, every bool
	}{
		{"arn:aws:dynamodb:*:*:table/orders/stream/*", true, true},
		{"arn:aws:dynamodb:*:*:table/orders/*", true, true},
		{"*", true, true},
		{"arn:aws:dynamodb:*:*:table/orders/stream/2026-01-05T10:00:00.000", true, false},
		{"arn:aws:dynamodb:*:*:table/orders", false, false},
		{"arn:aws:dynamodb:*:*:table/orders/index/*", false, false},
		{"arn:aws:dynamodb:*:*:table/users/stream/*", false, false},
	}
	for _, tt := range tests {
		st := Statement{Resource: Strings{tt.resource}}
		if got := st.MatchesStream(table); got != tt.any {
			t.Errorf("MatchesStream(%q) = %v, want %v", tt.resource, got, tt.any)
		}
		if got := st.MatchesEveryStream(table); got != tt.every {
			t.Errorf("MatchesEveryStream(%q) = %v, want %v", tt.resource, got, tt.every)
		}
	}
}

func TestNotResource(t *testing.T) {
	table := Table{Name: "orders"}
	other := Statement{NotResource: Strings{"arn:aws:dynamodb:*:*:table/users"}}
	if !other.MatchesTable(table) {
		t.Error("NotResource on another table should still cover orders")
	}
	same := Statement{NotResource: Strings{"arn:aws:dynamodb:*:*:table/orders"}}
	if same.MatchesTable(table) {
		t.Error("NotResource on orders should not cover orders")
	}
}
