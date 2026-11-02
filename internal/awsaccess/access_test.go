package awsaccess

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/MrShaaba/orgshift/internal/config"
)

type fakeSTS struct {
	account, arn string
	err          error
}

func (f fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Account: aws.String(f.account), Arn: aws.String(f.arn), UserId: aws.String("AROA123:orgshift")}, nil
}

func TestVerifyRefusesAnotherAccount(t *testing.T) {
	ctx := context.Background()
	id, err := Verify(ctx, fakeSTS{account: "111111111111", arn: "arn:aws:sts::111111111111:assumed-role/OrgshiftOrgRead/orgshift"}, "source management", "111111111111")
	if err != nil || id.AccountID != "111111111111" || id.UserID != "AROA123:orgshift" {
		t.Fatalf("matching identity: %+v %v", id, err)
	}
	id, err = Verify(ctx, fakeSTS{account: "999999999999", arn: "arn:aws:iam::999999999999:user/alice"}, "source management", "111111111111")
	var mm *MismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected a MismatchError, got %v", err)
	}
	if mm.Expected != "111111111111" || mm.Actual.AccountID != "999999999999" || id.AccountID != "999999999999" {
		t.Errorf("mismatch: %+v", mm)
	}
	for _, want := range []string{"source management", "999999999999", "alice", "111111111111", "refusing to continue"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q should mention %s", err.Error(), want)
		}
	}
	if _, err := Verify(ctx, fakeSTS{err: errors.New("ExpiredToken")}, "destination management", "222222222222"); err == nil || !strings.Contains(err.Error(), "destination management") || !strings.Contains(err.Error(), "ExpiredToken") || errors.As(err, &mm) {
		t.Errorf("STS failure is not a mismatch: %v", err)
	}
}

func writeSharedFiles(t *testing.T) (configFile, credsFile string) {
	t.Helper()
	dir := t.TempDir()
	configFile = filepath.Join(dir, "config")
	credsFile = filepath.Join(dir, "credentials")
	if err := os.WriteFile(configFile, []byte("[profile larkspur-mgmt]\nregion = eu-central-1\n\n[sso-session fernhill]\nsso_region = eu-west-1\nsso_start_url = https://fernhill.awsapps.com/start\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credsFile, []byte("[larkspur-mgmt]\naws_access_key_id = AKIAFAKEFAKEFAKEFAKE\naws_secret_access_key = fakefakefakefakefakefakefakefakefakefake\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return configFile, credsFile
}

func TestBuildProfileReadsSharedFilesWithoutNetwork(t *testing.T) {
	ctx := context.Background()
	configFile, credsFile := writeSharedFiles(t)
	opts := BuildOptions{HTTPClient: NoNetwork{}, SharedConfigFiles: []string{configFile}, SharedCredentialsFiles: []string{credsFile}, RetryAttempts: 3}
	cfg, err := Build(ctx, config.Access{AccountID: "111111111111", Profile: "larkspur-mgmt"}, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Region != "eu-central-1" {
		t.Errorf("region should come from the profile, got %q", cfg.Region)
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil || creds.AccessKeyID != "AKIAFAKEFAKEFAKEFAKE" {
		t.Errorf("static credentials from the profile: %+v %v", creds, err)
	}
	// The configured region wins over the profile's.
	cfg, err = Build(ctx, config.Access{AccountID: "111111111111", Profile: "larkspur-mgmt", Region: "us-east-1"}, nil, opts)
	if err != nil || cfg.Region != "us-east-1" {
		t.Errorf("configured region: %q %v", cfg.Region, err)
	}
	if _, err := Build(ctx, config.Access{AccountID: "111111111111", Profile: "missing"}, nil, opts); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("unknown profile: %v", err)
	}
}

func TestBuildSSOSessionUsesTheTokenCacheAndMakesNoCall(t *testing.T) {
	ctx := context.Background()
	configFile, credsFile := writeSharedFiles(t)
	tokenFile := filepath.Join(t.TempDir(), "token.json")
	asked := ""
	opts := BuildOptions{HTTPClient: NoNetwork{}, SharedConfigFiles: []string{configFile}, SharedCredentialsFiles: []string{credsFile},
		TokenCachePath: func(session string) (string, error) { asked = session; return tokenFile, nil }}
	a := config.Access{AccountID: "222222222222", Region: "eu-west-1", SSOSession: "fernhill", SSORegion: "eu-west-1", SSORoleName: "OrgshiftOrgRead"}
	cfg, err := Build(ctx, a, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if asked != "fernhill" || cfg.Region != "eu-west-1" {
		t.Errorf("session %q region %q", asked, cfg.Region)
	}
	// Without a cached token the provider fails before any request: the
	// error names the token, not the test HTTP client.
	if _, err := cfg.Credentials.Retrieve(ctx); err == nil || strings.Contains(err.Error(), "no network") || !strings.Contains(strings.ToLower(err.Error()), "token") {
		t.Errorf("expected a token cache error with no network call, got %v", err)
	}
	// With an expired cached token the provider must refresh through the
	// OIDC endpoint, which the test client refuses: proof that the chain is
	// wired to the SSO region and that nothing else was called.
	expired := `{"accessToken":"old","expiresAt":"2020-01-01T00:00:00Z","refreshToken":"r","clientId":"c","clientSecret":"s","region":"eu-west-1","startUrl":"https://fernhill.awsapps.com/start"}`
	if err := os.WriteFile(tokenFile, []byte(expired), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _ = Build(ctx, a, nil, opts)
	if _, err := cfg.Credentials.Retrieve(ctx); err == nil || !strings.Contains(err.Error(), "no network") || !strings.Contains(err.Error(), "oidc.eu-west-1.amazonaws.com") {
		t.Errorf("expected the refresh to be refused by the test client against the SSO region, got %v", err)
	}
}

func TestBuildAssumeRoleChainFromManagement(t *testing.T) {
	ctx := context.Background()
	configFile, credsFile := writeSharedFiles(t)
	opts := BuildOptions{HTTPClient: NoNetwork{}, SharedConfigFiles: []string{configFile}, SharedCredentialsFiles: []string{credsFile}}
	base, err := Build(ctx, config.Access{AccountID: "111111111111", Profile: "larkspur-mgmt", Region: "us-east-1"}, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	net := config.Access{AccountID: "111111111120", Region: "us-west-2", From: "management", AssumeRole: []config.RoleHop{
		{RoleARN: "arn:aws:iam::111111111120:role/OrgshiftNetworkRead", ExternalID: "x", Duration: config.Duration(time.Hour)},
	}}
	cfg, err := Build(ctx, net, &base, opts)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Region != "us-west-2" || base.Region != "us-east-1" {
		t.Errorf("the hop gets its own region and the base is untouched: %q %q", cfg.Region, base.Region)
	}
	// Resolving the chain calls sts:AssumeRole, which the test client
	// refuses against the STS endpoint: the chain is wired, nothing else ran.
	if _, err := cfg.Credentials.Retrieve(ctx); err == nil || !strings.Contains(err.Error(), "no network") || !strings.Contains(err.Error(), "sts.") {
		t.Errorf("expected the assume-role call to be refused by the test client, got %v", err)
	}
	if _, err := Build(ctx, net, nil, opts); err == nil || !strings.Contains(err.Error(), "management configuration") {
		t.Errorf("from management without a base: %v", err)
	}
	// A hop on top of a profile works the same way.
	withHop := config.Access{AccountID: "111111111111", Profile: "larkspur-mgmt", AssumeRole: []config.RoleHop{{RoleARN: "arn:aws:iam::111111111111:role/OrgshiftOrgRead"}}}
	cfg, err = Build(ctx, withHop, nil, opts)
	if err != nil || cfg.Region != "eu-central-1" {
		t.Fatalf("profile with hop: %q %v", cfg.Region, err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err == nil || !strings.Contains(err.Error(), "no network") {
		t.Errorf("expected the hop to be refused by the test client, got %v", err)
	}
}

func TestBuildNeedsARegion(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "config")
	if err := os.WriteFile(empty, []byte("[profile noregion]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	_, err := Build(context.Background(), config.Access{AccountID: "111111111111", Profile: "noregion"}, nil, BuildOptions{HTTPClient: NoNetwork{}, SharedConfigFiles: []string{empty}, SharedCredentialsFiles: []string{empty}})
	if err == nil || !strings.Contains(err.Error(), "no region") {
		t.Errorf("expected a region error, got %v", err)
	}
}
