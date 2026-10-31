package usage

import (
	"testing"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func TestParseActions(t *testing.T) {
	acts, err := ParseActions([]byte(`["ec2:RunInstances","s3:GetObject"]`))
	if err != nil || len(acts) != 2 || acts[0].Source != "manual" {
		t.Fatalf("string array: %v %+v", err, acts)
	}
	acts, err = ParseActions([]byte(`{"actions":[{"action":"rds:CreateDBInstance","regions":["us-east-1"],"note":"x"}]}`))
	if err != nil || len(acts) != 1 || acts[0].Regions[0] != "us-east-1" {
		t.Fatalf("object form: %v %+v", err, acts)
	}
	if _, err := ParseActions([]byte(`["notanaction"]`)); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestParseLastAccessed(t *testing.T) {
	data := []byte(`{"JobStatus":"COMPLETED","JobType":"ACTION_LEVEL","ServicesLastAccessed":[
		{"ServiceName":"Amazon EC2","ServiceNamespace":"ec2","LastAuthenticated":"2025-12-01T00:00:00Z","LastAuthenticatedRegion":"us-east-1",
		 "TrackedActionsLastAccessed":[{"ActionName":"DescribeInstances","LastAccessedTime":"2025-12-01T00:00:00Z","LastAccessedRegion":"us-east-1"},{"ActionName":"ec2:RunInstances","LastAccessedTime":"2025-11-01T00:00:00Z"},{"ActionName":"TerminateInstances"}]},
		{"ServiceName":"Amazon DynamoDB","ServiceNamespace":"dynamodb","LastAuthenticated":"2025-12-02T00:00:00Z"},
		{"ServiceName":"Amazon Redshift","ServiceNamespace":"redshift"}
	]}`)
	acts, err := ParseLastAccessed(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, a := range acts {
		got[a.Action] = true
		if a.Source != "iam-last-accessed" {
			t.Errorf("source should be iam-last-accessed: %+v", a)
		}
	}
	for _, want := range []string{"ec2:DescribeInstances", "ec2:RunInstances", "dynamodb:*"} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if got["redshift:*"] || got["ec2:TerminateInstances"] {
		t.Errorf("never-used services and untimed actions must be skipped: %v", got)
	}
	if _, err := ParseLastAccessed([]byte(`{"JobStatus":"IN_PROGRESS"}`)); err == nil {
		t.Fatal("empty export should fail")
	}
}

func TestMerge(t *testing.T) {
	out := Merge([]snapshot.ActionInUse{{Action: "s3:GetObject", Note: "old"}}, []snapshot.ActionInUse{{Action: "S3:GetObject", Note: "new"}, {Action: "kms:Decrypt"}})
	if len(out) != 2 || out[0].Note != "new" || out[1].Action != "kms:Decrypt" {
		t.Fatalf("merge wrong: %+v", out)
	}
}
