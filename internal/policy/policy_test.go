package policy

import (
	"net/url"
	"reflect"
	"strconv"
	"testing"
)

func TestParseSingleStatement(t *testing.T) {
	doc, err := Parse([]byte(`{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"Action": "dynamodb:GetItem",
			"Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/orders"
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("got %d statements, want 1", len(doc.Statement))
	}
	st := doc.Statement[0]
	if !reflect.DeepEqual(st.Action, Strings{"dynamodb:GetItem"}) {
		t.Errorf("action = %v", st.Action)
	}
}

func TestParseListsAndConditions(t *testing.T) {
	doc, err := Parse([]byte(`{
		"Statement": [{
			"Sid": "Read",
			"Effect": "Allow",
			"Action": ["dynamodb:GetItem", "dynamodb:Query"],
			"Resource": ["*"],
			"Condition": {
				"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["${aws:PrincipalTag/org}"]},
				"Null": {"dynamodb:LeadingKeys": false},
				"NumericLessThan": {"aws:MultiFactorAuthAge": 3600}
			}
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	c := doc.Statement[0].Condition
	if got := c["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"]; !reflect.DeepEqual(got, Strings{"${aws:PrincipalTag/org}"}) {
		t.Errorf("leading keys = %v", got)
	}
	if got := c["Null"]["dynamodb:LeadingKeys"]; !reflect.DeepEqual(got, Strings{"false"}) {
		t.Errorf("null check = %v", got)
	}
	if got := c["NumericLessThan"]["aws:MultiFactorAuthAge"]; !reflect.DeepEqual(got, Strings{"3600"}) {
		t.Errorf("number = %v", got)
	}
}

func TestParseEncoded(t *testing.T) {
	plain := `{"Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"*"}]}`
	encoded := url.QueryEscape(plain)

	for name, in := range map[string]string{
		"url encoded":        encoded,
		"quoted url encoded": strconv.Quote(encoded),
		"quoted json":        strconv.Quote(plain),
	} {
		doc, err := Parse([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(doc.Statement) != 1 || doc.Statement[0].Action[0] != "dynamodb:Scan" {
			t.Errorf("%s: got %+v", name, doc.Statement)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "not json", `{"Statement": [{"Action": {"a": 1}}]}`} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%q) should fail", in)
		}
	}
}
