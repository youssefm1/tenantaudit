// Package policy parses IAM policy documents.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Document is an IAM policy document.
type Document struct {
	Version   string     `json:"Version"`
	Statement Statements `json:"Statement"`
}

// Statement is one statement in a policy.
type Statement struct {
	Sid         string     `json:"Sid"`
	Effect      string     `json:"Effect"`
	Action      Strings    `json:"Action"`
	NotAction   Strings    `json:"NotAction"`
	Resource    Strings    `json:"Resource"`
	NotResource Strings    `json:"NotResource"`
	Condition   Conditions `json:"Condition"`
}

// Conditions maps operator -> condition key -> values.
type Conditions map[string]map[string]Strings

// Statements accepts a single statement or a list. IAM allows both.
type Statements []Statement

func (s *Statements) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '{' {
		var one Statement
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = Statements{one}
		return nil
	}
	var many []Statement
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// Strings accepts a single value or a list. Condition values can also be
// bools or numbers, so those are kept as their string form.
type Strings []string

func (s *Strings) UnmarshalJSON(b []byte) error {
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case nil:
		*s = nil
	case []any:
		out := make(Strings, 0, len(v))
		for _, item := range v {
			str, err := scalar(item)
			if err != nil {
				return err
			}
			out = append(out, str)
		}
		*s = out
	default:
		str, err := scalar(v)
		if err != nil {
			return err
		}
		*s = Strings{str}
	}
	return nil
}

func scalar(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	}
	return "", fmt.Errorf("unexpected value %v in policy", v)
}

// Parse reads a policy document. IAM APIs return documents URL-encoded and
// the AWS CLI returns them as plain JSON, so both forms are accepted, either
// raw or wrapped in a JSON string.
func Parse(data []byte) (*Document, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty policy document")
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		data = []byte(strings.TrimSpace(s))
	}
	if len(data) > 0 && data[0] == '%' {
		decoded, err := url.QueryUnescape(string(data))
		if err != nil {
			return nil, fmt.Errorf("decode policy: %w", err)
		}
		data = []byte(decoded)
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return &doc, nil
}
