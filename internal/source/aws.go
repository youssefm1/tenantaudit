package source

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// IAMAPI is the part of the IAM client the loader needs.
type IAMAPI interface {
	GetAccountAuthorizationDetails(ctx context.Context, in *iam.GetAccountAuthorizationDetailsInput, opts ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
	GetPolicy(ctx context.Context, in *iam.GetPolicyInput, opts ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, in *iam.GetPolicyVersionInput, opts ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

// FromAWS reads every role in the account with its inline and managed
// policies. It needs iam:GetAccountAuthorizationDetails, iam:GetPolicy and
// iam:GetPolicyVersion.
func FromAWS(ctx context.Context, client IAMAPI) (*Account, error) {
	var d details

	in := &iam.GetAccountAuthorizationDetailsInput{
		// AWS managed policies are left out here and fetched only when a
		// role uses one. Asking for all of them returns over a thousand.
		Filter: []types.EntityType{types.EntityTypeRole, types.EntityTypeLocalManagedPolicy},
	}
	for {
		out, err := client.GetAccountAuthorizationDetails(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("get account authorization details: %w", err)
		}
		for _, r := range out.RoleDetailList {
			d.RoleDetailList = append(d.RoleDetailList, convertRole(r))
		}
		for _, p := range out.Policies {
			d.Policies = append(d.Policies, convertPolicy(p))
		}
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		in.Marker = out.Marker
	}

	fetch := func(arn string) ([]byte, error) {
		pol, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
		if err != nil {
			return nil, err
		}
		if pol.Policy == nil || pol.Policy.DefaultVersionId == nil {
			return nil, fmt.Errorf("no default version")
		}
		ver, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: aws.String(arn),
			VersionId: pol.Policy.DefaultVersionId,
		})
		if err != nil {
			return nil, err
		}
		if ver.PolicyVersion == nil || ver.PolicyVersion.Document == nil {
			return nil, fmt.Errorf("empty policy document")
		}
		return []byte(*ver.PolicyVersion.Document), nil
	}

	return build(d, fetch), nil
}

func convertRole(r types.RoleDetail) roleDetail {
	rd := roleDetail{
		RoleName: aws.ToString(r.RoleName),
		Arn:      aws.ToString(r.Arn),
		Path:     aws.ToString(r.Path),
	}
	for _, p := range r.RolePolicyList {
		rd.RolePolicyList = append(rd.RolePolicyList, inlinePolicy{
			PolicyName:     aws.ToString(p.PolicyName),
			PolicyDocument: json.RawMessage(aws.ToString(p.PolicyDocument)),
		})
	}
	for _, p := range r.AttachedManagedPolicies {
		rd.AttachedManagedPolicies = append(rd.AttachedManagedPolicies, attachedPolicy{
			PolicyName: aws.ToString(p.PolicyName),
			PolicyArn:  aws.ToString(p.PolicyArn),
		})
	}
	return rd
}

func convertPolicy(p types.ManagedPolicyDetail) managedPolicy {
	mp := managedPolicy{PolicyName: aws.ToString(p.PolicyName), Arn: aws.ToString(p.Arn)}
	for _, v := range p.PolicyVersionList {
		mp.PolicyVersionList = append(mp.PolicyVersionList, policyVersion{
			Document:         json.RawMessage(aws.ToString(v.Document)),
			IsDefaultVersion: v.IsDefaultVersion,
		})
	}
	return mp
}
