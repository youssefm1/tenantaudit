// Package audit decides whether a role's access to a table is limited to
// one tenant's partition keys.
package audit

import (
	"strings"

	"github.com/youssefm1/tenantaudit/internal/policy"
)

const leadingKeysKey = "dynamodb:leadingkeys"

// keyScope describes how a statement's conditions restrict partition keys.
type keyScope struct {
	// present is true when a condition limits dynamodb:LeadingKeys.
	present bool
	// patterns are the allowed partition key values or patterns.
	patterns []string
	// globs are the patterns that came from StringLike, where * and ? are
	// wildcards. Under StringEquals they are plain characters.
	globs []string
	// anyValue is true when the only restriction uses ForAnyValue, which
	// passes when a single key in a batch request matches.
	anyValue bool
	// requiresKey is true when a Null check rejects requests that carry no
	// partition key, such as Scan.
	requiresKey bool
}

// leadingKeys reads the dynamodb:LeadingKeys restrictions on a statement.
func leadingKeys(conds policy.Conditions) keyScope {
	var scope keyScope
	var forAll, forAny, globAll, globAny []string

	for op, keys := range conds {
		modifier, base := splitOperator(op)
		for key, values := range keys {
			if strings.ToLower(key) != leadingKeysKey {
				continue
			}
			switch {
			case base == "null":
				for _, v := range values {
					if strings.EqualFold(v, "false") {
						scope.requiresKey = true
					}
				}
			case isStringMatch(base):
				like := base == "stringlike"
				if modifier == "foranyvalue" {
					forAny = append(forAny, values...)
					if like {
						globAny = append(globAny, values...)
					}
				} else {
					forAll = append(forAll, values...)
					if like {
						globAll = append(globAll, values...)
					}
				}
			}
		}
	}

	switch {
	case len(forAll) > 0:
		scope.present = true
		scope.patterns = forAll
		scope.globs = globAll
	case len(forAny) > 0:
		scope.present = true
		scope.anyValue = true
		scope.patterns = forAny
		scope.globs = globAny
	}
	return scope
}

// matchesEverything reports whether one of the patterns allows any key.
func (k keyScope) matchesEverything() bool {
	for _, p := range k.patterns {
		if strings.Trim(p, "*") == "" {
			return true
		}
	}
	return false
}

// usesPrefix reports whether every pattern starts with the tenant prefix.
func (k keyScope) usesPrefix(prefix string) bool {
	for _, p := range k.patterns {
		if !strings.HasPrefix(p, prefix) {
			return false
		}
	}
	return true
}

// splitOperator breaks "ForAllValues:StringEqualsIfExists" into
// ("forallvalues", "stringequals").
func splitOperator(op string) (modifier, base string) {
	op = strings.ToLower(op)
	if i := strings.Index(op, ":"); i >= 0 {
		modifier, op = op[:i], op[i+1:]
	}
	return modifier, strings.TrimSuffix(op, "ifexists")
}

func isStringMatch(base string) bool {
	switch base {
	case "stringequals", "stringequalsignorecase", "stringlike":
		return true
	}
	return false
}
