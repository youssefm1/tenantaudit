// Package source loads IAM roles and their policies.
package source

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/youssefm1/tenantaudit/internal/audit"
	"github.com/youssefm1/tenantaudit/internal/policy"
)

// Account is the set of roles found, plus anything that could not be read.
// A warning means a role may have more access than the audit shows.
type Account struct {
	Roles    []audit.Role
	Warnings []string
}

// details mirrors the output of `aws iam get-account-authorization-details`.
type details struct {
	RoleDetailList []roleDetail    `json:"RoleDetailList"`
	Policies       []managedPolicy `json:"Policies"`
}

type roleDetail struct {
	RoleName                string           `json:"RoleName"`
	Arn                     string           `json:"Arn"`
	Path                    string           `json:"Path"`
	RolePolicyList          []inlinePolicy   `json:"RolePolicyList"`
	AttachedManagedPolicies []attachedPolicy `json:"AttachedManagedPolicies"`
}

type inlinePolicy struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyDocument json.RawMessage `json:"PolicyDocument"`
}

type attachedPolicy struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type managedPolicy struct {
	PolicyName        string          `json:"PolicyName"`
	Arn               string          `json:"Arn"`
	PolicyVersionList []policyVersion `json:"PolicyVersionList"`
}

type policyVersion struct {
	Document         json.RawMessage `json:"Document"`
	IsDefaultVersion bool            `json:"IsDefaultVersion"`
}

// fetchFunc returns the default version of a managed policy that was not in
// the account details.
type fetchFunc func(arn string) ([]byte, error)

// FromFile reads a file saved from
//
//	aws iam get-account-authorization-details > account.json
func FromFile(path string) (*Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d details
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if d.RoleDetailList == nil {
		return nil, fmt.Errorf("%s: no RoleDetailList, expected output of get-account-authorization-details", path)
	}
	return build(d, nil), nil
}

// build turns account details into roles with parsed policies.
func build(d details, fetch fetchFunc) *Account {
	acct := &Account{}
	warn := func(format string, args ...any) {
		acct.Warnings = append(acct.Warnings, fmt.Sprintf(format, args...))
	}

	// Parse each managed policy once, however many roles use it.
	managed := map[string]*policy.Document{}
	for _, p := range d.Policies {
		for _, v := range p.PolicyVersionList {
			if !v.IsDefaultVersion {
				continue
			}
			doc, err := policy.Parse(v.Document)
			if err != nil {
				warn("managed policy %s: %v", p.PolicyName, err)
				continue
			}
			managed[p.Arn] = doc
		}
	}
	failed := map[string]bool{}

	for _, rd := range d.RoleDetailList {
		// Service-linked roles are managed by AWS and can't be changed.
		if strings.HasPrefix(rd.Path, "/aws-service-role/") {
			continue
		}
		role := audit.Role{Name: rd.RoleName, ARN: rd.Arn}

		for _, ip := range rd.RolePolicyList {
			doc, err := policy.Parse(ip.PolicyDocument)
			if err != nil {
				warn("role %s: inline policy %s: %v", rd.RoleName, ip.PolicyName, err)
				continue
			}
			role.Policies = append(role.Policies, audit.Policy{Name: ip.PolicyName, Document: doc})
		}

		for _, ap := range rd.AttachedManagedPolicies {
			doc, ok := managed[ap.PolicyArn]
			if !ok && fetch != nil && !failed[ap.PolicyArn] {
				raw, err := fetch(ap.PolicyArn)
				if err == nil {
					doc, err = policy.Parse(raw)
				}
				if err != nil {
					failed[ap.PolicyArn] = true
					warn("managed policy %s: %v", ap.PolicyName, err)
				} else {
					managed[ap.PolicyArn] = doc
					ok = true
				}
			}
			if !ok {
				warn("role %s: managed policy %s was not checked", rd.RoleName, ap.PolicyName)
				continue
			}
			role.Policies = append(role.Policies, audit.Policy{Name: ap.PolicyName, Document: doc})
		}

		acct.Roles = append(acct.Roles, role)
	}

	sort.Slice(acct.Roles, func(a, b int) bool { return acct.Roles[a].Name < acct.Roles[b].Name })
	return acct
}
