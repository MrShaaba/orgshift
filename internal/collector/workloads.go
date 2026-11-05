package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
	retypes "github.com/aws/aws-sdk-go-v2/service/resourceexplorer2/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// StackSetsAPI is the subset of the CloudFormation client the collector
// uses in the management account to read the StackSets administered there.
type StackSetsAPI interface {
	ListStackSets(context.Context, *cloudformation.ListStackSetsInput, ...func(*cloudformation.Options)) (*cloudformation.ListStackSetsOutput, error)
	DescribeStackSet(context.Context, *cloudformation.DescribeStackSetInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStackSetOutput, error)
	ListStackInstances(context.Context, *cloudformation.ListStackInstancesInput, ...func(*cloudformation.Options)) (*cloudformation.ListStackInstancesOutput, error)
}

// StacksAPI is the subset of the CloudFormation client the collector uses
// inside a member account, in one Region.
type StacksAPI interface {
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	ListStackResources(context.Context, *cloudformation.ListStackResourcesInput, ...func(*cloudformation.Options)) (*cloudformation.ListStackResourcesOutput, error)
	ListExports(context.Context, *cloudformation.ListExportsInput, ...func(*cloudformation.Options)) (*cloudformation.ListExportsOutput, error)
	ListImports(context.Context, *cloudformation.ListImportsInput, ...func(*cloudformation.Options)) (*cloudformation.ListImportsOutput, error)
	GetTemplate(context.Context, *cloudformation.GetTemplateInput, ...func(*cloudformation.Options)) (*cloudformation.GetTemplateOutput, error)
}

// TaggingAPI reads the tagged resource sample of one Region.
type TaggingAPI interface {
	GetResources(context.Context, *resourcegroupstaggingapi.GetResourcesInput, ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error)
}

// ResourceExplorerAPI finds an aggregator index and searches it.
type ResourceExplorerAPI interface {
	ListIndexes(context.Context, *resourceexplorer2.ListIndexesInput, ...func(*resourceexplorer2.Options)) (*resourceexplorer2.ListIndexesOutput, error)
	Search(context.Context, *resourceexplorer2.SearchInput, ...func(*resourceexplorer2.Options)) (*resourceexplorer2.SearchOutput, error)
}

// BucketsAPI reads bucket policies. S3 bills both calls per request, so
// the collector only uses it behind the bucket-policies opt-in.
type BucketsAPI interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
}

// RolesAPI lists the account's roles with their trust policies.
type RolesAPI interface {
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
}

// MemberClients are the clients of one member account in one Region,
// obtained through the member inspection role.
type MemberClients struct {
	Stacks           StacksAPI
	Tagging          TaggingAPI
	ResourceExplorer ResourceExplorerAPI
	// Buckets is nil unless the bucket-policies opt-in is on.
	Buckets BucketsAPI
	Roles   RolesAPI
}

// MemberClientFactory returns the clients of a member account in a Region.
// Credentials resolve lazily, so a denied sts:AssumeRole shows up as the
// error of the first call made with them.
type MemberClientFactory func(ctx context.Context, accountID, region string) (*MemberClients, error)

// Resource sample sources a configuration can ask for.
const (
	ResourceSourceAuto = "auto"
)

// Default caps of the workload inventory, per account.
const (
	DefaultMaxStacks    = 500
	DefaultMaxResources = 1000
	DefaultMaxBuckets   = 200
	DefaultMaxRoles     = 2000
	// maxExports bounds the ListImports calls per Region.
	maxExports = 500
)

// WorkloadOptions configure the member-account inventory.
type WorkloadOptions struct {
	// Accounts are the member accounts to inspect.
	Accounts []string
	// Regions are the workload Regions; empty means the collector's Region.
	Regions []string
	// Clients builds the clients of one account and Region.
	Clients MemberClientFactory
	// ResourceSource is auto (Resource Explorer when the account has an
	// aggregator index, otherwise the Tagging API), tagging-api or
	// resource-explorer.
	ResourceSource string
	// BucketPolicies turns on the S3 reads, which S3 bills per request.
	BucketPolicies bool
	// Caps per account; zero means the default.
	MaxStacks, MaxResources, MaxBuckets, MaxRoles int
}

func (w *WorkloadOptions) withDefaults() WorkloadOptions {
	out := *w
	if out.MaxStacks <= 0 {
		out.MaxStacks = DefaultMaxStacks
	}
	if out.MaxResources <= 0 {
		out.MaxResources = DefaultMaxResources
	}
	if out.MaxBuckets <= 0 {
		out.MaxBuckets = DefaultMaxBuckets
	}
	if out.MaxRoles <= 0 {
		out.MaxRoles = DefaultMaxRoles
	}
	if out.ResourceSource == "" {
		out.ResourceSource = ResourceSourceAuto
	}
	return out
}

// BucketPoliciesSkipped is the reason recorded when bucket policies are not
// read because the opt-in is off.
const BucketPoliciesSkipped = "bucket policies were not read: S3 bills ListBuckets and GetBucketPolicy per request, so they are read only with billable.bucket_policies (--with-bucket-policies); role trust policies and policies declared in templates were read"

// stackSets reads the StackSets administered from the management account:
// their permission model, targets, automatic deployment settings and the
// stack instances they have in member accounts.
func (r *run) stackSets() {
	domain := snapshot.DomainStackSets
	ops := []string{"cloudformation:ListStackSets", "cloudformation:DescribeStackSet", "cloudformation:ListStackInstances"}
	client := r.opts.StackSets
	if client == nil {
		d := r.skipped(domain)
		d.Region = r.opts.Region
		r.record(d)
		return
	}
	var names []string
	pager := cloudformation.NewListStackSetsPaginator(client, &cloudformation.ListStackSetsInput{Status: cfntypes.StackSetStatusActive})
	pages, err := r.paginate(domain, ops[0], pager.HasMorePages, func() error {
		page, err := pager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, s := range page.Summaries {
			names = append(names, aws.ToString(s.StackSetName))
		}
		return nil
	})
	if err != nil {
		d := r.failedAt(domain, err, pages, 0, ops[0])
		d.Region = r.opts.Region
		r.record(d)
		return
	}
	type result struct {
		set   snapshot.StackSet
		pages int
		err   error
	}
	results := make([]result, len(names))
	r.parallel(len(names), func(i int) {
		name := names[i]
		var out *cloudformation.DescribeStackSetOutput
		if err := r.call(domain, ops[1], func() error {
			var err error
			out, err = client.DescribeStackSet(r.ctx, &cloudformation.DescribeStackSetInput{StackSetName: aws.String(name)})
			return err
		}); err != nil {
			results[i] = result{err: fmt.Errorf("StackSet %s: %w", name, err)}
			return
		}
		ss := out.StackSet
		if ss == nil {
			results[i] = result{err: fmt.Errorf("StackSet %s: empty description", name)}
			return
		}
		set := snapshot.StackSet{Name: name, ID: aws.ToString(ss.StackSetId), PermissionModel: string(ss.PermissionModel), Description: aws.ToString(ss.Description),
			TargetOUs: append([]string(nil), ss.OrganizationalUnitIds...), Regions: append([]string(nil), ss.Regions...)}
		if ad := ss.AutoDeployment; ad != nil {
			set.AutoDeployment = aws.ToBool(ad.Enabled)
			set.RetainStacksOnAccountRemoval = aws.ToBool(ad.RetainStacksOnAccountRemoval)
		}
		// A self-managed StackSet names its administration role; a
		// service-managed one is administered by the account that lists it.
		set.AdministrationAccountID = snapshot.AccountFromARN(aws.ToString(ss.AdministrationRoleARN))
		if set.AdministrationAccountID == "" {
			set.AdministrationAccountID = snapshot.AccountFromARN(aws.ToString(ss.StackSetARN))
		}
		accounts := map[string]bool{}
		ip := cloudformation.NewListStackInstancesPaginator(client, &cloudformation.ListStackInstancesInput{StackSetName: aws.String(name)})
		pn, err := r.paginate(domain, ops[2], ip.HasMorePages, func() error {
			page, err := ip.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, in := range page.Summaries {
				set.Instances = append(set.Instances, snapshot.StackInstance{AccountID: aws.ToString(in.Account), Region: aws.ToString(in.Region), StackID: aws.ToString(in.StackId),
					Status: string(in.Status), OrganizationalUnitID: aws.ToString(in.OrganizationalUnitId)})
				accounts[aws.ToString(in.Account)] = true
			}
			return nil
		})
		if err != nil {
			results[i] = result{pages: pn, err: fmt.Errorf("instances of StackSet %s: %w", name, err)}
			return
		}
		if set.PermissionModel != string(cfntypes.PermissionModelsServiceManaged) {
			for a := range accounts {
				set.TargetAccounts = append(set.TargetAccounts, a)
			}
			sort.Strings(set.TargetAccounts)
		}
		sort.Strings(set.Regions)
		results[i] = result{set: set, pages: pn + 1}
	})
	items := 0
	var firstErr error
	for _, res := range results {
		pages += res.pages
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		r.snap.StackSets = append(r.snap.StackSets, res.set)
		items++
	}
	var d snapshot.DomainCoverage
	if firstErr != nil {
		d = r.failedAt(domain, firstErr, pages, items, ops...)
	} else {
		d = r.observed(domain, items, pages, ops...)
		d.Reason = "StackSets administered from the calling account; StackSets of a CloudFormation delegated administrator are listed only from that account"
	}
	d.Region = r.opts.Region
	r.record(d)
}

// failedAt records a failed domain like failed, and keeps what the call was
// about (which stack, which StackSet, which Region) in front of the API
// error, so the record says where to look.
func (r *run) failedAt(domain string, err error, pages, items int, ops ...string) snapshot.DomainCoverage {
	rec := r.failed(domain, err, pages, items, ops...)
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if i := strings.Index(err.Error(), apiErr.Error()); i > 0 {
			rec.Error = err.Error()[:i] + rec.Error
		}
	}
	return rec
}

// accountWorkload is the outcome of inspecting one member account.
type accountWorkload struct {
	inv     *snapshot.AccountWorkloads
	records []snapshot.DomainCoverage
}

// workloads reads the workload inventory of every configured member
// account: stacks, a resource sample and the policies conditioned on
// organization identity.
func (r *run) workloads() {
	if r.opts.Workloads == nil || r.opts.Workloads.Clients == nil || len(r.opts.Workloads.Accounts) == 0 {
		for _, d := range snapshot.WorkloadDomains {
			rec := r.skipped(d)
			if r.opts.SkipReasons[d] == "" {
				rec.Reason = "no member account was inspected: name the accounts to move under member_inspection.accounts"
			}
			r.record(rec)
		}
		return
	}
	w := r.opts.Workloads.withDefaults()
	if len(w.Regions) == 0 {
		w.Regions = []string{r.opts.Region}
	}
	known := map[string]bool{}
	for _, a := range r.snap.Accounts {
		known[a.ID] = true
	}
	results := make([]accountWorkload, len(w.Accounts))
	r.parallel(len(w.Accounts), func(i int) {
		account := w.Accounts[i]
		if !known[account] {
			// A configured account that the organization does not have is a
			// configuration error for that account, not for the collection.
			for _, d := range snapshot.WorkloadDomains {
				results[i].records = append(results[i].records, snapshot.DomainCoverage{Domain: d, Status: snapshot.CoverageError, AccountID: account,
					Error: fmt.Sprintf("account %s is named under member_inspection.accounts but is not an account of organization %s", account, r.snap.Organization.ID)})
			}
			return
		}
		results[i] = r.accountWorkloads(&w, account)
	})
	for i, res := range results {
		if res.inv != nil {
			if r.snap.Workloads == nil {
				r.snap.Workloads = map[string]*snapshot.AccountWorkloads{}
			}
			r.snap.Workloads[w.Accounts[i]] = res.inv
		}
		for _, rec := range res.records {
			r.record(rec)
		}
	}
}

// accountWorkloads inspects one account. Each domain gets its own record,
// so a denied call in one does not hide what the others read.
func (r *run) accountWorkloads(w *WorkloadOptions, account string) accountWorkload {
	inv := &snapshot.AccountWorkloads{Regions: append([]string(nil), w.Regions...), Stacks: []snapshot.Stack{}, Resources: []snapshot.WorkloadResource{},
		ResourcePolicies: []snapshot.ResourcePolicy{}, CollectedAt: r.snap.GeneratedAt}
	out := accountWorkload{inv: inv}
	clients := map[string]*MemberClients{}
	for _, region := range w.Regions {
		c, err := w.Clients(r.ctx, account, region)
		if err != nil || c == nil {
			if err == nil {
				err = errors.New("no clients for the member account")
			}
			for _, d := range snapshot.WorkloadDomains {
				rec := r.failedAt(d, fmt.Errorf("member role in %s (%s): %w", account, region, err), 0, 0, "sts:AssumeRole")
				rec.AccountID = account
				out.records = append(out.records, rec)
			}
			out.inv = nil
			return out
		}
		clients[region] = c
	}
	first := clients[w.Regions[0]]

	stackRec, templatePolicies := r.accountStacks(w, account, clients, inv)
	out.records = append(out.records, stackRec)
	out.records = append(out.records, r.accountResources(w, account, clients, inv))
	out.records = append(out.records, r.accountPolicies(w, account, first, clients, inv, templatePolicies)...)
	// Nothing at all could be read: no inventory, only the records.
	readable := false
	for _, rec := range out.records {
		if rec.Status.Complete() || rec.Status == snapshot.CoveragePartial {
			readable = true
		}
	}
	if !readable {
		out.inv = nil
	}
	return out
}

// accountStacks reads the stacks of the account in every workload Region.
// It returns the coverage record and the policies found in templates.
func (r *run) accountStacks(w *WorkloadOptions, account string, clients map[string]*MemberClients, inv *snapshot.AccountWorkloads) (snapshot.DomainCoverage, []snapshot.ResourcePolicy) {
	domain := snapshot.DomainWorkloadStacks
	ops := []string{"cloudformation:DescribeStacks", "cloudformation:ListStackResources", "cloudformation:ListExports", "cloudformation:ListImports", "cloudformation:GetTemplate"}
	var policies []snapshot.ResourcePolicy
	pages := 0
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	capped := false
	for _, region := range w.Regions {
		client := clients[region].Stacks
		if client == nil {
			note(fmt.Errorf("no CloudFormation client for %s", region))
			continue
		}
		var described []cfntypes.Stack
		pager := cloudformation.NewDescribeStacksPaginator(client, &cloudformation.DescribeStacksInput{})
		pn, err := r.paginate(domain, ops[0], pager.HasMorePages, func() error {
			page, err := pager.NextPage(r.ctx)
			if err != nil {
				return err
			}
			described = append(described, page.Stacks...)
			return nil
		})
		pages += pn
		if err != nil {
			note(fmt.Errorf("stacks in %s: %w", region, err))
			if pn == 0 {
				continue
			}
		}
		// Imports, from the exporting side: every export of the Region and
		// the stacks that import it.
		importsOf := map[string][]snapshot.StackImport{}
		exports := 0
		ep := cloudformation.NewListExportsPaginator(client, &cloudformation.ListExportsInput{})
		type export struct{ name, stack string }
		var exported []export
		pn, err = r.paginate(domain, ops[2], ep.HasMorePages, func() error {
			page, err := ep.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, e := range page.Exports {
				exported = append(exported, export{name: aws.ToString(e.Name), stack: stackNameFromID(aws.ToString(e.ExportingStackId))})
			}
			return nil
		})
		pages += pn
		if err != nil {
			note(fmt.Errorf("exports in %s: %w", region, err))
		}
		for _, e := range exported {
			if exports >= maxExports {
				capped = true
				break
			}
			exports++
			ip := cloudformation.NewListImportsPaginator(client, &cloudformation.ListImportsInput{ExportName: aws.String(e.name)})
			pn, err := r.paginate(domain, ops[3], ip.HasMorePages, func() error {
				page, err := ip.NextPage(r.ctx)
				if err != nil {
					return err
				}
				for _, importer := range page.Imports {
					importsOf[importer] = append(importsOf[importer], snapshot.StackImport{ExportName: e.name, ExportingStack: e.stack})
				}
				return nil
			})
			pages += pn
			// CloudFormation answers ListImports for an export nobody
			// imports with a ValidationError rather than an empty list.
			// The API reference does not document it; it is read as "no
			// importer", which is what the message says.
			if err != nil && errorCode(err) != "ValidationError" {
				note(fmt.Errorf("imports of %s in %s: %w", e.name, region, err))
			}
		}
		for _, d := range described {
			if len(inv.Stacks) >= w.MaxStacks {
				capped = true
				break
			}
			name := aws.ToString(d.StackName)
			st := snapshot.Stack{Name: name, ID: aws.ToString(d.StackId), Region: region, Status: string(d.StackStatus), Description: aws.ToString(d.Description),
				TerminationProtection: aws.ToBool(d.EnableTerminationProtection), ParentID: aws.ToString(d.ParentId), ResourceTypes: map[string]int{}}
			if d.CreationTime != nil {
				st.CreatedAt = d.CreationTime.UTC().Format(time.RFC3339)
			}
			if d.LastUpdatedTime != nil {
				st.UpdatedAt = d.LastUpdatedTime.UTC().Format(time.RFC3339)
			}
			if len(d.Tags) > 0 {
				st.Tags = map[string]string{}
				for _, t := range d.Tags {
					st.Tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
			}
			// Output keys and export names are kept; output values are not,
			// because a stack can output anything.
			for _, o := range d.Outputs {
				st.Outputs = append(st.Outputs, snapshot.StackOutput{Key: aws.ToString(o.OutputKey), ExportName: aws.ToString(o.ExportName)})
			}
			st.Imports = importsOf[name]
			// Parameter values are read for identifiers of infrastructure
			// only (subnets, transit gateways); the values themselves are
			// not stored.
			params := map[string]string{}
			seen := map[string]bool{}
			for _, p := range d.Parameters {
				key, val := aws.ToString(p.ParameterKey), aws.ToString(p.ParameterValue)
				if p.ResolvedValue != nil {
					val = aws.ToString(p.ResolvedValue)
				}
				params[key] = val
				for _, ref := range referencesIn(val, "parameter "+key) {
					if !seen[ref.ID] {
						seen[ref.ID] = true
						st.References = append(st.References, ref)
					}
				}
			}
			if rest := snapshot.StackSetNameFromStack(name); rest != "" {
				st.StackSet = &snapshot.StackSetRef{Name: rest, Evidence: snapshot.StackSetEvidenceName}
			}
			rp := cloudformation.NewListStackResourcesPaginator(client, &cloudformation.ListStackResourcesInput{StackName: aws.String(name)})
			pn, err := r.paginate(domain, ops[1], rp.HasMorePages, func() error {
				page, err := rp.NextPage(r.ctx)
				if err != nil {
					return err
				}
				for _, res := range page.StackResourceSummaries {
					st.ResourceTypes[aws.ToString(res.ResourceType)]++
				}
				return nil
			})
			pages += pn
			if err != nil {
				note(fmt.Errorf("resources of stack %s in %s: %w", name, region, err))
			}
			var tmpl *cloudformation.GetTemplateOutput
			err = r.call(domain, ops[4], func() error {
				var err error
				tmpl, err = client.GetTemplate(r.ctx, &cloudformation.GetTemplateInput{StackName: aws.String(name)})
				return err
			})
			switch {
			case err != nil:
				note(fmt.Errorf("template of stack %s in %s: %w", name, region, err))
			case tmpl != nil && tmpl.TemplateBody != nil:
				pages++
				parsed, perr := parseTemplate(aws.ToString(tmpl.TemplateBody))
				if perr != nil {
					note(fmt.Errorf("template of stack %s in %s: %w", name, region, perr))
					break
				}
				facts := factsOfTemplate(parsed, name, params)
				st.ExternalOutputs = facts.externalOutputs
				for _, ref := range facts.references {
					if !seen[ref.ID] {
						seen[ref.ID] = true
						st.References = append(st.References, ref)
					}
				}
				policies = append(policies, facts.policies...)
			}
			inv.Stacks = append(inv.Stacks, st)
		}
	}
	var rec snapshot.DomainCoverage
	switch {
	case firstErr != nil:
		rec = r.failedAt(domain, firstErr, pages, len(inv.Stacks), ops...)
	case capped:
		rec = snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoveragePartial, Items: len(inv.Stacks), Pages: pages, Operations: ops,
			Error: fmt.Sprintf("capped: more than %d stacks or %d exports; raise workloads.max_stacks", w.MaxStacks, maxExports)}
	default:
		rec = r.observed(domain, len(inv.Stacks), pages, ops...)
		rec.Reason = "regions " + strings.Join(w.Regions, ", ")
	}
	rec.AccountID = account
	return rec, policies
}

// stackNameFromID returns the stack name inside a stack ARN.
func stackNameFromID(id string) string {
	if i := strings.Index(id, ":stack/"); i >= 0 {
		rest := id[i+len(":stack/"):]
		if j := strings.Index(rest, "/"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return id
}

// accountResources reads the resource sample: from Resource Explorer when
// the account has an aggregator index and the source allows it, otherwise
// from the Resource Groups Tagging API. The source used is recorded.
func (r *run) accountResources(w *WorkloadOptions, account string, clients map[string]*MemberClients, inv *snapshot.AccountWorkloads) snapshot.DomainCoverage {
	domain := snapshot.DomainWorkloadResources
	first := clients[w.Regions[0]]
	fallback := ""
	if w.ResourceSource != snapshot.ResourceSourceTaggingAPI {
		rec, used, why := r.explorerSample(w, account, first, inv)
		if used {
			return rec
		}
		if w.ResourceSource == snapshot.ResourceSourceResourceExplorer {
			rec.AccountID = account
			return rec
		}
		fallback = why
	}
	ops := []string{"tag:GetResources"}
	pages := 0
	capped := false
	var firstErr error
	for _, region := range w.Regions {
		client := clients[region].Tagging
		if client == nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("no Tagging API client for %s", region)
			}
			continue
		}
		pager := resourcegroupstaggingapi.NewGetResourcesPaginator(client, &resourcegroupstaggingapi.GetResourcesInput{ResourcesPerPage: aws.Int32(100)})
		for pager.HasMorePages() && !capped {
			err := r.call(domain, ops[0], func() error {
				page, err := pager.NextPage(r.ctx)
				if err != nil {
					return err
				}
				for _, m := range page.ResourceTagMappingList {
					if len(inv.Resources) >= w.MaxResources {
						capped = true
						break
					}
					arn := aws.ToString(m.ResourceARN)
					res := snapshot.WorkloadResource{ARN: arn, Type: snapshot.TypeFromARN(arn), Region: region, Tags: map[string]string{}}
					for _, t := range m.Tags {
						res.Tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
					}
					res.Stack = res.Tags["aws:cloudformation:stack-name"]
					inv.Resources = append(inv.Resources, res)
				}
				return nil
			})
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("resources in %s: %w", region, err)
				}
				break
			}
			pages++
		}
	}
	inv.ResourceSource = snapshot.ResourceSourceTaggingAPI
	inv.ResourcesTruncated = capped
	var rec snapshot.DomainCoverage
	if firstErr != nil {
		rec = r.failedAt(domain, firstErr, pages, len(inv.Resources), ops...)
	} else {
		rec = r.observed(domain, len(inv.Resources), pages, ops...)
		rec.Reason = "a sample from the Resource Groups Tagging API, which returns resources that are or were tagged, never untagged ones"
		if capped {
			rec.Reason += fmt.Sprintf("; capped at %d resources (workloads.max_resources)", w.MaxResources)
		}
		if fallback != "" {
			rec.Reason += "; Resource Explorer was not used: " + fallback
		}
	}
	rec.AccountID = account
	return rec
}

// explorerSample tries Resource Explorer. used is false when the Tagging
// API should be tried instead, with the reason.
func (r *run) explorerSample(w *WorkloadOptions, account string, first *MemberClients, inv *snapshot.AccountWorkloads) (rec snapshot.DomainCoverage, used bool, why string) {
	domain := snapshot.DomainWorkloadResources
	ops := []string{"resource-explorer-2:ListIndexes", "resource-explorer-2:Search"}
	if first.ResourceExplorer == nil {
		return r.failedAt(domain, errors.New("no Resource Explorer client"), 0, 0, ops...), false, "no Resource Explorer client"
	}
	aggregator := ""
	pages := 0
	lp := resourceexplorer2.NewListIndexesPaginator(first.ResourceExplorer, &resourceexplorer2.ListIndexesInput{Type: retypes.IndexTypeAggregator})
	pn, err := r.paginate(domain, ops[0], lp.HasMorePages, func() error {
		page, err := lp.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, ix := range page.Indexes {
			if ix.Type == retypes.IndexTypeAggregator && aggregator == "" {
				aggregator = aws.ToString(ix.Region)
			}
		}
		return nil
	})
	pages += pn
	if err != nil {
		_, msg := classify(err)
		return r.failedAt(domain, fmt.Errorf("resource explorer indexes: %w", err), pages, 0, ops[0]), false, "listing its indexes failed (" + msg + ")"
	}
	if aggregator == "" {
		return r.failedAt(domain, errors.New("the account has no Resource Explorer aggregator index"), pages, 0, ops[0]), false, "the account has no aggregator index"
	}
	searcher := first.ResourceExplorer
	if aggregator != w.Regions[0] {
		c, err := w.Clients(r.ctx, account, aggregator)
		if err != nil || c == nil || c.ResourceExplorer == nil {
			return r.failedAt(domain, fmt.Errorf("no client for the aggregator Region %s", aggregator), pages, 0, ops...), false, "no client for the aggregator Region " + aggregator
		}
		searcher = c.ResourceExplorer
	}
	wanted := map[string]bool{"global": true}
	for _, region := range w.Regions {
		wanted[region] = true
	}
	var found []snapshot.WorkloadResource
	returned := 0
	sp := resourceexplorer2.NewSearchPaginator(searcher, &resourceexplorer2.SearchInput{QueryString: aws.String(""), MaxResults: aws.Int32(1000)})
	capped := false
	for sp.HasMorePages() && !capped {
		err := r.call(domain, ops[1], func() error {
			page, err := sp.NextPage(r.ctx)
			if err != nil {
				return err
			}
			for _, res := range page.Resources {
				returned++
				if !wanted[aws.ToString(res.Region)] {
					continue
				}
				if len(found) >= w.MaxResources {
					capped = true
					break
				}
				arn := aws.ToString(res.Arn)
				item := snapshot.WorkloadResource{ARN: arn, Type: aws.ToString(res.ResourceType), Region: aws.ToString(res.Region), Tags: explorerTags(res.Properties)}
				if item.Type == "" {
					item.Type = snapshot.TypeFromARN(arn)
				}
				item.Stack = item.Tags["aws:cloudformation:stack-name"]
				found = append(found, item)
			}
			return nil
		})
		if err != nil {
			// A Region without a default view answers Search with an error;
			// the Tagging API is the documented alternative.
			_, msg := classify(err)
			return r.failedAt(domain, fmt.Errorf("resource explorer search in %s: %w", aggregator, err), pages, 0, ops...), false, "its search in " + aggregator + " failed (" + msg + ")"
		}
		pages++
	}
	inv.Resources = append(inv.Resources, found...)
	inv.ResourceSource = snapshot.ResourceSourceResourceExplorer
	// Search returns only the first 1,000 results of a query.
	inv.ResourcesTruncated = capped || returned >= 1000
	rec = r.observed(domain, len(found), pages, ops...)
	rec.Reason = "a sample from the Resource Explorer aggregator index in " + aggregator
	if inv.ResourcesTruncated {
		rec.Reason += "; Search returns only the first 1,000 results, so the sample is incomplete"
	}
	rec.AccountID = account
	return rec, true, ""
}

// explorerTags reads the tags property of a Resource Explorer result.
func explorerTags(props []retypes.ResourceProperty) map[string]string {
	tags := map[string]string{}
	for _, p := range props {
		if aws.ToString(p.Name) != "tags" || p.Data == nil {
			continue
		}
		var list []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		}
		data, err := p.Data.MarshalSmithyDocument()
		if err != nil || json.Unmarshal(data, &list) != nil {
			continue
		}
		for _, t := range list {
			tags[t.Key] = t.Value
		}
	}
	return tags
}

// accountPolicies reads the role trust policies and, with the opt-in, the
// bucket policies of the account, keeps those conditioned on organization
// identity and adds the ones found in templates.
func (r *run) accountPolicies(w *WorkloadOptions, account string, first *MemberClients, clients map[string]*MemberClients, inv *snapshot.AccountWorkloads, fromTemplates []snapshot.ResourcePolicy) []snapshot.DomainCoverage {
	domain := snapshot.DomainWorkloadPolicies
	ops := []string{"iam:ListRoles"}
	pages := 0
	var firstErr error
	capped := false
	keep := func(kind, arn, source, doc string) {
		inv.PoliciesInspected++
		conds, err := snapshot.ExtractOrgConditions(json.RawMessage(doc))
		if err != nil || len(conds) == 0 {
			return
		}
		inv.ResourcePolicies = append(inv.ResourcePolicies, snapshot.ResourcePolicy{Kind: kind, ResourceARN: arn, Source: source, Document: json.RawMessage(doc), Conditions: conds})
	}
	if first.Roles == nil {
		firstErr = errors.New("no IAM client")
	} else {
		roles := 0
		pager := iam.NewListRolesPaginator(first.Roles, &iam.ListRolesInput{MaxItems: aws.Int32(200)})
		for pager.HasMorePages() && !capped {
			err := r.call(domain, ops[0], func() error {
				page, err := pager.NextPage(r.ctx)
				if err != nil {
					return err
				}
				for _, role := range page.Roles {
					if roles >= w.MaxRoles {
						capped = true
						break
					}
					roles++
					keep(snapshot.PolicyKindRoleTrust, aws.ToString(role.Arn), "iam:ListRoles", decodePolicy(aws.ToString(role.AssumeRolePolicyDocument)))
				}
				return nil
			})
			if err != nil {
				firstErr = fmt.Errorf("roles: %w", err)
				break
			}
			pages++
		}
	}
	inv.PoliciesInspected += len(fromTemplates)
	inv.ResourcePolicies = append(inv.ResourcePolicies, fromTemplates...)

	var bucketErr error
	if w.BucketPolicies {
		ops = append(ops, "s3:ListBuckets", "s3:GetBucketPolicy")
		pn, err := r.bucketPolicies(w, first, clients, keep, &capped)
		pages += pn
		bucketErr = err
	}
	var recs []snapshot.DomainCoverage
	var rec snapshot.DomainCoverage
	switch {
	case firstErr != nil:
		rec = r.failedAt(domain, firstErr, pages, len(inv.ResourcePolicies), ops...)
	case bucketErr != nil:
		rec = r.failedAt(domain, bucketErr, pages, len(inv.ResourcePolicies), ops...)
		rec.Status = snapshot.CoveragePartial
	case capped:
		rec = snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoveragePartial, Items: len(inv.ResourcePolicies), Pages: pages, Operations: ops,
			Error: fmt.Sprintf("capped: more than %d roles or %d buckets; raise workloads.max_roles or workloads.max_buckets", w.MaxRoles, w.MaxBuckets)}
	default:
		rec = r.observed(domain, len(inv.ResourcePolicies), pages, ops...)
		rec.Reason = fmt.Sprintf("%d policies read, %d reference organization identity", inv.PoliciesInspected, len(inv.ResourcePolicies))
	}
	rec.AccountID = account
	recs = append(recs, rec)
	if !w.BucketPolicies {
		recs = append(recs, snapshot.DomainCoverage{Domain: domain, Status: snapshot.CoverageSkipped, AccountID: account, Reason: BucketPoliciesSkipped})
	}
	return recs
}

// bucketPolicies reads the policy of every bucket in the workload Regions.
// Only called with the opt-in: S3 bills both calls per request.
func (r *run) bucketPolicies(w *WorkloadOptions, first *MemberClients, clients map[string]*MemberClients, keep func(kind, arn, source, doc string), capped *bool) (int, error) {
	domain := snapshot.DomainWorkloadPolicies
	if first.Buckets == nil {
		return 0, errors.New("no S3 client")
	}
	type bucket struct{ name, region string }
	var buckets []bucket
	pager := s3.NewListBucketsPaginator(first.Buckets, &s3.ListBucketsInput{})
	pages, err := r.paginate(domain, "s3:ListBuckets", pager.HasMorePages, func() error {
		page, err := pager.NextPage(r.ctx)
		if err != nil {
			return err
		}
		for _, b := range page.Buckets {
			buckets = append(buckets, bucket{name: aws.ToString(b.Name), region: aws.ToString(b.BucketRegion)})
		}
		return nil
	})
	if err != nil {
		return pages, fmt.Errorf("buckets: %w", err)
	}
	var firstErr error
	read := 0
	for _, b := range buckets {
		c := clients[b.region]
		if b.region == "" {
			c = first
		}
		if c == nil || c.Buckets == nil {
			continue // a bucket outside the workload Regions
		}
		if read >= w.MaxBuckets {
			*capped = true
			break
		}
		read++
		var out *s3.GetBucketPolicyOutput
		err := r.call(domain, "s3:GetBucketPolicy", func() error {
			var err error
			out, err = c.Buckets.GetBucketPolicy(r.ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(b.name)})
			return err
		})
		pages++
		if err != nil {
			// A bucket without a policy answers NoSuchBucketPolicy.
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchBucketPolicy" {
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("policy of bucket %s: %w", b.name, err)
			}
			continue
		}
		if out != nil && out.Policy != nil {
			keep(snapshot.PolicyKindBucket, "arn:aws:s3:::"+b.name, "s3:GetBucketPolicy", aws.ToString(out.Policy))
		}
	}
	return pages, firstErr
}

// decodePolicy returns the JSON of a policy that IAM may return
// URL-encoded (RFC 3986), as the API reference says it does.
func decodePolicy(doc string) string {
	if strings.HasPrefix(strings.TrimSpace(doc), "{") {
		return doc
	}
	if dec, err := url.PathUnescape(doc); err == nil {
		return dec
	}
	return doc
}
