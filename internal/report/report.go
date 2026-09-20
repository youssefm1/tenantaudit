// Package report prints audit results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/youssefm1/tenantaudit/internal/audit"
)

// Report is everything one run found for a table.
type Report struct {
	Table        string
	RolesChecked int
	Results      []audit.Result
	Warnings     []string
}

// New keeps the roles that can reach the table, worst first.
func New(table string, results []audit.Result, warnings []string) Report {
	r := Report{Table: table, RolesChecked: len(results), Warnings: warnings}
	for _, res := range results {
		if res.Level != audit.NoAccess {
			r.Results = append(r.Results, res)
		}
	}
	sort.SliceStable(r.Results, func(a, b int) bool {
		if r.Results[a].Level != r.Results[b].Level {
			return r.Results[a].Level > r.Results[b].Level
		}
		return r.Results[a].Role < r.Results[b].Role
	})
	return r
}

// CrossTenant counts roles that can reach more than one tenant's items.
func (r Report) CrossTenant() int {
	n := 0
	for _, res := range r.Results {
		if res.Level >= audit.Unscoped {
			n++
		}
	}
	return n
}

// Text writes a table for people to read.
func (r Report) Text(w io.Writer) error {
	fmt.Fprintf(w, "%s\n", r.Table)
	if len(r.Results) == 0 {
		fmt.Fprintf(w, "  no roles can read or write items (%d checked)\n", r.RolesChecked)
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, res := range r.Results {
		mark := "✗"
		if res.Level == audit.Scoped {
			mark = "✓"
		}
		// Show the grants behind the role's level. Lesser grants on the
		// same role don't change the outcome.
		first := true
		for _, g := range res.Grants {
			if g.Level != res.Level {
				continue
			}
			name, level := res.Role, res.Level.String()
			if !first {
				mark, name, level = " ", "", ""
			}
			fmt.Fprintf(tw, "  %s %s\t%s\t%s\t%s\t(%s, %s)\n", mark, name, level, actions(g.Actions), g.Note, g.Policy, g.Statement)
			first = false
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintf(w, "\n%d of %d roles with access can reach other tenants' items\n", r.CrossTenant(), len(r.Results))
	return nil
}

// actions shortens a list like dynamodb:GetItem, dynamodb:Query, ...
func actions(list []string) string {
	const show = 3
	short := make([]string, 0, len(list))
	for _, a := range list {
		short = append(short, strings.TrimPrefix(a, "dynamodb:"))
	}
	if len(short) <= show {
		return strings.Join(short, ", ")
	}
	return fmt.Sprintf("%s +%d more", strings.Join(short[:show], ", "), len(short)-show)
}

type jsonReport struct {
	Table    string      `json:"table"`
	Summary  jsonSummary `json:"summary"`
	Roles    []jsonRole  `json:"roles"`
	Warnings []string    `json:"warnings"`
}

type jsonSummary struct {
	RolesChecked int `json:"roles_checked"`
	WithAccess   int `json:"with_access"`
	CrossTenant  int `json:"cross_tenant"`
}

type jsonRole struct {
	Role   string      `json:"role"`
	ARN    string      `json:"arn,omitempty"`
	Level  string      `json:"level"`
	Grants []jsonGrant `json:"grants"`
}

type jsonGrant struct {
	Policy    string   `json:"policy"`
	Statement string   `json:"statement"`
	Level     string   `json:"level"`
	Actions   []string `json:"actions"`
	Note      string   `json:"note"`
}

// JSON writes the full result, including grants below each role's level.
func (r Report) JSON(w io.Writer) error {
	out := jsonReport{
		Table:    r.Table,
		Summary:  jsonSummary{RolesChecked: r.RolesChecked, WithAccess: len(r.Results), CrossTenant: r.CrossTenant()},
		Roles:    []jsonRole{},
		Warnings: r.Warnings,
	}
	if out.Warnings == nil {
		out.Warnings = []string{}
	}
	for _, res := range r.Results {
		role := jsonRole{Role: res.Role, ARN: res.ARN, Level: res.Level.String(), Grants: []jsonGrant{}}
		for _, g := range res.Grants {
			role.Grants = append(role.Grants, jsonGrant{
				Policy: g.Policy, Statement: g.Statement, Level: g.Level.String(), Actions: g.Actions, Note: g.Note,
			})
		}
		out.Roles = append(out.Roles, role)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
