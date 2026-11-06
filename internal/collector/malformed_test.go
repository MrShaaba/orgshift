package collector

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// fakeOrgsBroken is the fake organization with three more SCPs whose
// documents are malformed in different ways.
type fakeOrgsBroken struct{ fakeOrgs }

var brokenDocs = map[string]string{
	"p-both00001": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:*","NotAction":"s3:*","Resource":"*"}]}`,
	"p-noact0001": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Resource":"*"}]}`,
	"p-nores0001": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:RunInstances"}]}`,
	"p-nojson001": `{"Version": "2012-10-17", "Statement": [`,
}

func (fakeOrgsBroken) ListPolicies(_ context.Context, in *organizations.ListPoliciesInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	out := &organizations.ListPoliciesOutput{Policies: []orgtypes.PolicySummary{{Id: aws.String("p-FullAWSAccess"), Name: aws.String("FullAWSAccess"), AwsManaged: true, Type: orgtypes.PolicyTypeServiceControlPolicy}}}
	for _, id := range []string{"p-both00001", "p-noact0001", "p-nores0001", "p-nojson001"} {
		out.Policies = append(out.Policies, orgtypes.PolicySummary{Id: aws.String(id), Name: aws.String("Broken-" + id[2:7]), Type: orgtypes.PolicyTypeServiceControlPolicy})
	}
	return out, nil
}

func (f fakeOrgsBroken) DescribePolicy(ctx context.Context, in *organizations.DescribePolicyInput, o ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if doc, ok := brokenDocs[aws.ToString(in.PolicyId)]; ok {
		return &organizations.DescribePolicyOutput{Policy: &orgtypes.Policy{Content: aws.String(doc)}}, nil
	}
	return f.fakeOrgs.DescribePolicy(ctx, in, o...)
}

// M5 defect 3: one malformed policy used to stop the collection ("collected
// snapshot failed validation"). The collector now records each one as
// malformed with the reason and carries on.
func TestMalformedPoliciesAreRecordedAndCollectionCarriesOn(t *testing.T) {
	snap, err := Collect(context.Background(), Options{Organizations: fakeOrgsBroken{}})
	if err != nil {
		t.Fatalf("malformed policies must not stop the collection: %v", err)
	}
	if err := snap.Validate(); err != nil {
		t.Fatalf("the collected snapshot is usable: %v", err)
	}
	if len(snap.Policies) != 5 {
		t.Fatalf("every policy is kept, got %d", len(snap.Policies))
	}
	reasons := map[string]string{}
	for _, p := range snap.Policies {
		reasons[p.ID] = p.Malformed
	}
	for id, want := range map[string]string{
		"p-both00001": "both Action and NotAction",
		"p-noact0001": "neither Action nor NotAction",
		"p-nores0001": "must include a Resource or NotResource element",
		"p-nojson001": "not valid JSON",
	} {
		if !strings.Contains(reasons[id], want) {
			t.Errorf("%s: recorded reason %q should contain %q", id, reasons[id], want)
		}
	}
	if reasons["p-FullAWSAccess"] != "" {
		t.Errorf("a well-formed policy carries no reason: %q", reasons["p-FullAWSAccess"])
	}
	// The domain was read completely; the record says what it holds.
	rec := record(t, snap, snapshot.DomainPoliciesSCP)
	if rec.Status != snapshot.CoverageObserved || rec.Items != 5 || !strings.Contains(rec.Reason, "4 malformed policy(ies) kept as found") {
		t.Errorf("coverage: %+v", rec)
	}
	if sum := Summary(snap); !strings.Contains(sum, "4 malformed policy(ies) kept as found") {
		t.Errorf("summary: %s", sum)
	}
	// The rest of the organization was collected as usual.
	if len(snap.Accounts) != 2 || record(t, snap, snapshot.DomainTree).Status != snapshot.CoverageObserved {
		t.Errorf("the other domains are unaffected: %d accounts", len(snap.Accounts))
	}
	// The snapshot survives a save and a load with the reasons in it.
	data, err := snapshot.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	back, err := snapshot.Parse(data)
	if err != nil {
		t.Fatalf("a snapshot with recorded malformed policies loads: %v", err)
	}
	if len(back.MalformedPolicies()) != 4 {
		t.Errorf("malformed policies after a round trip: %d", len(back.MalformedPolicies()))
	}
}
