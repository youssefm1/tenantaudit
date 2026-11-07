package policy

import (
	"regexp"
	"strings"
)

// Table identifies the DynamoDB table being audited. Region and Account are
// optional. When empty they match any value in a policy ARN.
type Table struct {
	Name    string
	Region  string
	Account string
}

// Glob matches s against an IAM pattern, where * matches any run of
// characters and ? matches exactly one.
func Glob(pattern, s string) bool {
	p, n := 0, 0
	star, mark := -1, 0
	for n < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[n]):
			p++
			n++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, n
			p++
		case star >= 0:
			p = star + 1
			mark++
			n = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// MatchesAction reports whether the statement applies to an action such as
// "dynamodb:Query". Action names are case-insensitive.
func (s Statement) MatchesAction(action string) bool {
	action = strings.ToLower(action)
	if len(s.NotAction) > 0 {
		return !anyGlob(s.NotAction, action, strings.ToLower)
	}
	return anyGlob(s.Action, action, strings.ToLower)
}

// MatchesTable reports whether the statement applies to the table itself.
func (s Statement) MatchesTable(t Table) bool {
	return s.matchesResource(t, "table/"+t.Name)
}

// MatchesIndex reports whether the statement applies to at least one index
// on the table.
func (s Statement) MatchesIndex(t Table) bool {
	if s.MatchesEveryIndex(t) {
		return true
	}
	if len(s.NotResource) > 0 {
		return false
	}
	// A resource can also name one index, like table/x/index/by-status.
	// The export doesn't list indexes, so assume it exists.
	for _, p := range s.Resource {
		if head, _, ok := strings.Cut(p, "/index/"); ok && matchARN(head, t, "table/"+t.Name) {
			return true
		}
	}
	return false
}

// MatchesEveryIndex reports whether the statement applies to any index the
// table could have, as table/x/index/* does.
func (s Statement) MatchesEveryIndex(t Table) bool {
	// A made-up index name only matches patterns that don't name one.
	return s.matchesResource(t, "table/"+t.Name+"/index/_")
}

func (s Statement) matchesResource(t Table, resource string) bool {
	if len(s.NotResource) > 0 {
		return !anyARN(s.NotResource, t, resource)
	}
	return anyARN(s.Resource, t, resource)
}

func anyGlob(patterns Strings, s string, norm func(string) string) bool {
	for _, p := range patterns {
		if Glob(norm(p), s) {
			return true
		}
	}
	return false
}

func anyARN(patterns Strings, t Table, resource string) bool {
	for _, p := range patterns {
		if matchARN(p, t, resource) {
			return true
		}
	}
	return false
}

var policyVar = regexp.MustCompile(`\$\{[^}]*\}`)

// matchARN compares an ARN pattern to a DynamoDB resource one field at a
// time, so an unknown region or account can be skipped.
func matchARN(pattern string, t Table, resource string) bool {
	// A policy variable resolves at request time, so treat it as a wildcard.
	pattern = policyVar.ReplaceAllString(pattern, "*")
	if pattern == "*" {
		return true
	}
	parts := strings.SplitN(pattern, ":", 6)
	// "arn:aws:dynamodb:*" is valid. The trailing * covers the missing fields.
	for len(parts) < 6 && strings.HasSuffix(parts[len(parts)-1], "*") {
		parts = append(parts, "*")
	}
	if len(parts) < 6 || parts[0] != "arn" {
		return false
	}
	if !Glob(parts[2], "dynamodb") {
		return false
	}
	if t.Region != "" && !Glob(parts[3], t.Region) {
		return false
	}
	if t.Account != "" && !Glob(parts[4], t.Account) {
		return false
	}
	return Glob(parts[5], resource)
}
