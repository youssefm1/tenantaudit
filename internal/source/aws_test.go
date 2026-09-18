package source

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// fakeIAM serves canned pages and records what was asked for.
type fakeIAM struct {
	pages         []*iam.GetAccountAuthorizationDetailsOutput
	detailCalls   int
	fetchedARNs   []string
	policyVersion map[string]string
}

func (f *fakeIAM) GetAccountAuthorizationDetails(_ context.Context, in *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	if f.detailCalls >= len(f.pages) {
		return nil, errors.New("no more pages")
	}
	page := f.pages[f.detailCalls]
	f.detailCalls++
	return page, nil
}

func (f *fakeIAM) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	if _, ok := f.policyVersion[*in.PolicyArn]; !ok {
		return nil, errors.New("NoSuchEntity")
	}
	return &iam.GetPolicyOutput{Policy: &types.Policy{DefaultVersionId: aws.String("v3")}}, nil
}

func (f *fakeIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	f.fetchedARNs = append(f.fetchedARNs, *in.PolicyArn+"@"+*in.VersionId)
	doc := f.policyVersion[*in.PolicyArn]
	return &iam.GetPolicyVersionOutput{PolicyVersion: &types.PolicyVersion{Document: aws.String(doc)}}, nil
}

func encoded(doc string) *string { return aws.String(url.QueryEscape(doc)) }

func TestFromAWS(t *testing.T) {
	const scanAll = `{"Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"*"}]}`
	const readOnly = "arn:aws:iam::aws:policy/ReadOnlyAccess"
	const local = "arn:aws:iam::111122223333:policy/local"

	fake := &fakeIAM{
		pages: []*iam.GetAccountAuthorizationDetailsOutput{
			{
				IsTruncated: true,
				Marker:      aws.String("next"),
				RoleDetailList: []types.RoleDetail{{
					RoleName:       aws.String("worker"),
					Arn:            aws.String("arn:aws:iam::111122223333:role/worker"),
					Path:           aws.String("/"),
					RolePolicyList: []types.PolicyDetail{{PolicyName: aws.String("inline"), PolicyDocument: encoded(scanAll)}},
					AttachedManagedPolicies: []types.AttachedPolicy{
						{PolicyName: aws.String("local"), PolicyArn: aws.String(local)},
						{PolicyName: aws.String("ReadOnlyAccess"), PolicyArn: aws.String(readOnly)},
					},
				}},
			},
			{
				RoleDetailList: []types.RoleDetail{{
					RoleName:                aws.String("api"),
					Path:                    aws.String("/"),
					AttachedManagedPolicies: []types.AttachedPolicy{{PolicyName: aws.String("ReadOnlyAccess"), PolicyArn: aws.String(readOnly)}},
				}},
				Policies: []types.ManagedPolicyDetail{{
					PolicyName: aws.String("local"),
					Arn:        aws.String(local),
					PolicyVersionList: []types.PolicyVersion{
						{Document: encoded(`{"Statement":[]}`), IsDefaultVersion: false},
						{Document: encoded(scanAll), IsDefaultVersion: true},
					},
				}},
			},
		},
		policyVersion: map[string]string{readOnly: url.QueryEscape(scanAll)},
	}

	acct, err := FromAWS(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}
	if fake.detailCalls != 2 {
		t.Errorf("read %d pages, want 2", fake.detailCalls)
	}
	if len(acct.Roles) != 2 || acct.Roles[0].Name != "api" || acct.Roles[1].Name != "worker" {
		t.Fatalf("roles = %+v", acct.Roles)
	}
	if got := len(acct.Roles[1].Policies); got != 3 {
		t.Errorf("worker has %d policies, want inline + local + ReadOnlyAccess", got)
	}
	if len(fake.fetchedARNs) != 1 || fake.fetchedARNs[0] != readOnly+"@v3" {
		t.Errorf("fetched %v, want ReadOnlyAccess default version once", fake.fetchedARNs)
	}
	if len(acct.Warnings) != 0 {
		t.Errorf("warnings = %v", acct.Warnings)
	}
}

func TestFromAWSError(t *testing.T) {
	if _, err := FromAWS(context.Background(), &fakeIAM{}); err == nil {
		t.Error("want an error when the first call fails")
	}
}
