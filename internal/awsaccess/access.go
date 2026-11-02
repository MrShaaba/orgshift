// Package awsaccess turns an onboarding Access into AWS SDK credentials
// (profiles, Identity Center sessions, assume-role chains) and verifies
// with sts:GetCallerIdentity that they belong to the account the
// configuration names. It is the only place orgshift builds credentials;
// nothing here calls AWS except WhoAmI, which the CLI runs before any
// collection and which tests exercise with a fake.
package awsaccess

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/MrShaaba/orgshift/internal/config"
)

// STSAPI is the subset of the STS client used to verify an identity.
type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Identity is what sts:GetCallerIdentity reports.
type Identity struct {
	AccountID string `json:"account_id"`
	ARN       string `json:"arn"`
	UserID    string `json:"user_id,omitempty"`
}

// WhoAmI asks STS who the credentials are.
func WhoAmI(ctx context.Context, api STSAPI) (Identity, error) {
	out, err := api.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}
	return Identity{AccountID: aws.ToString(out.Account), ARN: aws.ToString(out.Arn), UserID: aws.ToString(out.UserId)}, nil
}

// MismatchError says the credentials belong to another account than the
// configuration names. The CLI refuses to continue on it.
type MismatchError struct {
	// Label names the access ("source management").
	Label    string
	Expected string
	Actual   Identity
}

func (e *MismatchError) Error() string {
	return fmt.Sprintf("%s: the credentials belong to account %s (%s) but the configuration names account %s; refusing to continue", e.Label, e.Actual.AccountID, e.Actual.ARN, e.Expected)
}

// Verify resolves the identity and checks the account. It returns a
// *MismatchError when the account differs.
func Verify(ctx context.Context, api STSAPI, label, expectedAccount string) (Identity, error) {
	id, err := WhoAmI(ctx, api)
	if err != nil {
		return Identity{}, fmt.Errorf("%s: %w", label, err)
	}
	if id.AccountID != expectedAccount {
		return id, &MismatchError{Label: label, Expected: expectedAccount, Actual: id}
	}
	return id, nil
}

// BuildOptions tune Build. Tests use the file and cache overrides to keep
// everything offline.
type BuildOptions struct {
	// RetryAttempts is the SDK's maximum attempts per call (adaptive mode).
	RetryAttempts int
	// HTTPClient replaces the SDK's HTTP client.
	HTTPClient awsconfig.HTTPClient
	// SharedConfigFiles and SharedCredentialsFiles replace ~/.aws/config
	// and ~/.aws/credentials.
	SharedConfigFiles      []string
	SharedCredentialsFiles []string
	// TokenCachePath returns the cached SSO token file for a session name.
	// Defaults to the standard ~/.aws/sso/cache/<sha1(session)>.json.
	TokenCachePath func(session string) (string, error)
	// SessionName is the default role session name for assume-role hops.
	SessionName string
}

// Build turns an Access into an aws.Config. base is the side's management
// configuration, used when the access says "from: management"; it may be
// nil otherwise. Nothing is called: credentials are resolved lazily by the
// first API call (WhoAmI, from the CLI).
func Build(ctx context.Context, a config.Access, base *aws.Config, o BuildOptions) (aws.Config, error) {
	if o.SessionName == "" {
		o.SessionName = "orgshift"
	}
	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRetryMode(aws.RetryModeAdaptive)}
	if o.RetryAttempts > 0 {
		loadOpts = append(loadOpts, awsconfig.WithRetryMaxAttempts(o.RetryAttempts))
	}
	if a.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(a.Region))
	}
	if o.HTTPClient != nil {
		loadOpts = append(loadOpts, awsconfig.WithHTTPClient(o.HTTPClient))
	}
	if o.SharedConfigFiles != nil {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigFiles(o.SharedConfigFiles))
	}
	if o.SharedCredentialsFiles != nil {
		loadOpts = append(loadOpts, awsconfig.WithSharedCredentialsFiles(o.SharedCredentialsFiles))
	}
	var cfg aws.Config
	switch {
	case a.Profile != "":
		c, err := awsconfig.LoadDefaultConfig(ctx, append(loadOpts, awsconfig.WithSharedConfigProfile(a.Profile))...)
		if err != nil {
			return aws.Config{}, fmt.Errorf("profile %s: %w", a.Profile, err)
		}
		cfg = c
	case a.SSOSession != "":
		c, err := awsconfig.LoadDefaultConfig(ctx, append(loadOpts, awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}))...)
		if err != nil {
			return aws.Config{}, err
		}
		cfg = c
		cachePath := o.TokenCachePath
		if cachePath == nil {
			cachePath = ssocreds.StandardCachedTokenFilepath
		}
		tokenFile, err := cachePath(a.SSOSession)
		if err != nil {
			return aws.Config{}, fmt.Errorf("sso session %s: %w", a.SSOSession, err)
		}
		ssoCfg := cfg.Copy()
		ssoCfg.Region = a.SSORegion
		tokens := ssocreds.NewSSOTokenProvider(ssooidc.NewFromConfig(ssoCfg), tokenFile)
		provider := ssocreds.New(sso.NewFromConfig(ssoCfg), a.SSOAccount(), a.SSORoleName, a.SSOStartURL, func(po *ssocreds.Options) {
			po.SSOTokenProvider = tokens
			po.CachedTokenFilepath = tokenFile
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	case a.From == "management":
		if base == nil {
			return aws.Config{}, errors.New("from: management needs the management configuration")
		}
		cfg = base.Copy()
		if a.Region != "" {
			cfg.Region = a.Region
		}
	default:
		c, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
		if err != nil {
			return aws.Config{}, err
		}
		cfg = c
	}
	if cfg.Region == "" {
		return aws.Config{}, fmt.Errorf("no region for %s: set region in the configuration or the profile", a.Describe())
	}
	for _, hop := range a.AssumeRole {
		hop := hop
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), hop.RoleARN, func(ro *stscreds.AssumeRoleOptions) {
			ro.RoleSessionName = o.SessionName
			if hop.SessionName != "" {
				ro.RoleSessionName = hop.SessionName
			}
			if hop.ExternalID != "" {
				ro.ExternalID = aws.String(hop.ExternalID)
			}
			if hop.Duration > 0 {
				ro.Duration = time.Duration(hop.Duration)
			}
		})
		next := cfg.Copy()
		next.Credentials = aws.NewCredentialsCache(provider)
		cfg = next
	}
	return cfg, nil
}

// NoNetwork is an HTTP client that fails every request. Tests pass it as
// BuildOptions.HTTPClient to prove that building credentials makes no call.
type NoNetwork struct{}

// Do fails.
func (NoNetwork) Do(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("no network: %s %s refused by the test HTTP client", req.Method, req.URL.Host)
}

// Timeout is the default per-call timeout for identity checks.
const Timeout = 30 * time.Second
