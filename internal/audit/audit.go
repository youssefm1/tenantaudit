package audit

import (
	"fmt"
	"sort"

	"github.com/youssefm1/tenantaudit/internal/policy"
)

// Level is how far a role can reach into a table. Higher is worse.
type Level int

const (
	// NoAccess means no policy lets the role read or write items.
	NoAccess Level = iota
	// Scoped means every grant is limited to matching partition keys.
	Scoped
	// Unscoped means the role can use key-based actions on any tenant's items.
	Unscoped
	// ScanAll means the role can Scan, which returns every tenant's items.
	ScanAll
)

func (l Level) String() string {
	switch l {
	case Scoped:
		return "scoped"
	case Unscoped:
		return "unscoped"
	case ScanAll:
		return "scan"
	}
	return "none"
}

// Role is an IAM role and the identity policies attached to it.
type Role struct {
	Name     string
	ARN      string
	Policies []Policy
}

// Policy is a named policy document.
type Policy struct {
	Name     string
	Document *policy.Document
}

// Grant is one statement that gives the role access to the table.
type Grant struct {
	Policy    string
	Statement string
	Level     Level
	Actions   []string
	Note      string
}

// Result is the outcome for one role.
type Result struct {
	Role   string
	ARN    string
	Level  Level
	Grants []Grant
}

// Options tune the check.
type Options struct {
	// TenantKeyPrefix is the start of every tenant partition key, e.g. "org#".
	// When set, LeadingKeys patterns that don't start with it are noted.
	TenantKeyPrefix string
}

const scan = "dynamodb:Scan"

// keyActions read or write items by partition key, so LeadingKeys applies.
var keyActions = []string{
	"dynamodb:GetItem",
	"dynamodb:BatchGetItem",
	"dynamodb:Query",
	"dynamodb:TransactGetItems",
	"dynamodb:PartiQLSelect",
	"dynamodb:PutItem",
	"dynamodb:UpdateItem",
	"dynamodb:DeleteItem",
	"dynamodb:BatchWriteItem",
	"dynamodb:TransactWriteItems",
	"dynamodb:PartiQLInsert",
	"dynamodb:PartiQLUpdate",
	"dynamodb:PartiQLDelete",
}

// Check works out what a role can do to a table across tenants.
func Check(role Role, table policy.Table, opts Options) Result {
	res := Result{Role: role.Name, ARN: role.ARN}

	for _, p := range role.Policies {
		if p.Document == nil {
			continue
		}
		for i, st := range p.Document.Statement {
			if st.Effect != "Allow" {
				continue
			}
			onTable, onIndex := st.MatchesTable(table), st.MatchesIndex(table)
			if !onTable && !onIndex {
				continue
			}
			name := st.Sid
			if name == "" {
				name = fmt.Sprintf("statement %d", i+1)
			}
			scope := leadingKeys(st.Condition)

			// Collect actions by outcome so one statement gives one grant per level.
			byNote := map[string]*Grant{}
			add := func(action string, level Level, note string) {
				g, ok := byNote[note]
				if !ok {
					g = &Grant{Policy: p.Name, Statement: name, Level: level, Note: note}
					byNote[note] = g
				}
				g.Actions = append(g.Actions, action)
			}

			for _, action := range keyActions {
				if !st.MatchesAction(action) || denied(role, table, action, onTable) {
					continue
				}
				level, note := classify(scope, opts)
				add(action, level, note)
			}
			if st.MatchesAction(scan) && !denied(role, table, scan, onTable) && !scope.requiresKey {
				// Scan sends no partition key, and ForAllValues passes when
				// the key is missing, so LeadingKeys alone does not stop it.
				note := "Scan reads every tenant"
				if scope.present {
					note = "Scan is not limited by LeadingKeys without a Null check"
				}
				add(scan, ScanAll, note)
			}

			for _, g := range byNote {
				res.Grants = append(res.Grants, *g)
				if g.Level > res.Level {
					res.Level = g.Level
				}
			}
		}
	}

	sort.SliceStable(res.Grants, func(a, b int) bool {
		ga, gb := res.Grants[a], res.Grants[b]
		if ga.Level != gb.Level {
			return ga.Level > gb.Level
		}
		if ga.Policy != gb.Policy {
			return ga.Policy < gb.Policy
		}
		return ga.Statement < gb.Statement
	})
	return res
}

// classify decides the level for key-based actions under a statement.
func classify(scope keyScope, opts Options) (Level, string) {
	switch {
	case !scope.present:
		return Unscoped, "no tenant condition"
	case scope.matchesEverything():
		return Unscoped, "LeadingKeys allows every key"
	case scope.anyValue:
		return Unscoped, "ForAnyValue passes when one key in a batch matches"
	case opts.TenantKeyPrefix != "" && !scope.usesPrefix(opts.TenantKeyPrefix):
		return Scoped, fmt.Sprintf("scoped by LeadingKeys, but not to the %s prefix", opts.TenantKeyPrefix)
	}
	return Scoped, "scoped by LeadingKeys"
}

// denied reports whether an unconditional Deny blocks the action. A Deny
// with conditions is ignored, since it may or may not apply at request time.
func denied(role Role, table policy.Table, action string, onTable bool) bool {
	for _, p := range role.Policies {
		if p.Document == nil {
			continue
		}
		for _, st := range p.Document.Statement {
			if st.Effect != "Deny" || len(st.Condition) > 0 || !st.MatchesAction(action) {
				continue
			}
			if onTable && st.MatchesTable(table) {
				return true
			}
			if !onTable && st.MatchesIndex(table) {
				return true
			}
		}
	}
	return false
}
