package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// OUInput describes moving a whole OU, with every nested OU and account, under
// a new parent.
type OUInput struct {
	From *snapshot.Snapshot
	// To is the destination organization; nil means the same organization.
	To   *snapshot.Snapshot
	OUID string
	// TargetParentID is the root or OU the moved OU ends up under.
	TargetParentID string
	// TransferMethod is how each account changes organization when the move
	// is between organizations; see Input.TransferMethod.
	TransferMethod string
}

// OUResult is the outcome of one simulated OU move: the OU's own findings
// plus one full Result per account, rolled up into a single verdict.
type OUResult struct {
	Tool                string          `json:"tool"`
	ResultSchemaVersion int             `json:"result_schema_version"`
	Subject             OUSubject       `json:"subject"`
	Verdict             Status          `json:"verdict"`
	Summary             string          `json:"summary"`
	Findings            []Finding       `json:"findings"`
	Accounts            []AccountRollup `json:"accounts"`
	Attachments         []OUAttachment  `json:"attachments"`
	Diff                []Diff          `json:"diff"`
	Notes               []string        `json:"notes,omitempty"`
}

// OUSubject describes which OU moves where.
type OUSubject struct {
	OUID           string          `json:"ou_id"`
	OUName         string          `json:"ou_name"`
	SourceOrg      OrgRef          `json:"source_org"`
	TargetOrg      OrgRef          `json:"target_org"`
	CrossOrg       bool            `json:"cross_org"`
	SourcePath     []snapshot.Node `json:"source_path"`
	TargetPath     []snapshot.Node `json:"target_path"`
	SourceParentID string          `json:"source_parent_id"`
	TargetParentID string          `json:"target_parent_id"`
	// TransferMethod is how the accounts change organization (cross_org
	// only). An account that is the source's management account has a
	// procedure of its own, named in its result.
	TransferMethod string `json:"transfer_method,omitempty"`
	NestedOUs      int    `json:"nested_ous"`
	Accounts       int    `json:"accounts"`
}

// AccountRollup is one row of the per-account table.
type AccountRollup struct {
	AccountID    string `json:"account_id"`
	AccountName  string `json:"account_name"`
	RelativePath string `json:"relative_path"`
	Verdict      Status `json:"verdict"`
	Blocking     int    `json:"blocking"`
	Review       int    `json:"review"`
	Info         int    `json:"info"`
	// BlockingTitles lists the NO-GO finding titles, de-duplicated, so the
	// table can say why without opening the account.
	BlockingTitles []string `json:"blocking_titles,omitempty"`
	Result         *Result  `json:"result"`
}

// OUAttachment is a policy attached directly to the moved OU or one of its
// nested OUs, and what happens to it.
type OUAttachment struct {
	OUID       string `json:"ou_id"`
	OUName     string `json:"ou_name"`
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	PolicyType string `json:"policy_type"`
	AWSManaged bool   `json:"aws_managed"`
	// ControlTowerManaged marks an aws-guardrails-* SCP.
	ControlTowerManaged bool `json:"control_tower_managed,omitempty"`
	// Fate is "carried" for a move inside the organization; across
	// organizations it is "recreate" for customer-managed policies,
	// "automatic" for the AWS managed defaults Organizations attaches itself
	// and "control-tower" for guardrails, which Control Tower re-attaches
	// when the recreated OU is registered.
	Fate string `json:"fate"`
}

// EvaluateOU evaluates every account under an OU against the OU's new
// position and rolls the results up.
func EvaluateOU(in OUInput) (*OUResult, error) {
	if in.From == nil {
		return nil, fmt.Errorf("a source snapshot is required")
	}
	if err := ValidTransferMethod(in.TransferMethod); err != nil {
		return nil, err
	}
	to := in.To
	if to == nil {
		to = in.From
	}
	fromIx, toIx := in.From.Index(), to.Index()
	ou, ok := fromIx.OUByID[in.OUID]
	if !ok {
		return nil, fmt.Errorf("OU %s is not in the source snapshot (%s); roots cannot be moved", in.OUID, in.From.Organization.ID)
	}
	parentNode, ok := toIx.Node(in.TargetParentID)
	if !ok || parentNode.Kind == snapshot.KindAccount {
		return nil, fmt.Errorf("target %q is not a root or OU in the destination snapshot (%s)", in.TargetParentID, to.Organization.ID)
	}
	crossOrg := in.From.Organization.ID != to.Organization.ID
	if !crossOrg && toIx.IsUnder(in.TargetParentID, ou.ID) {
		return nil, fmt.Errorf("OU %s cannot be moved under itself (%s)", ou.ID, in.TargetParentID)
	}
	ous, accounts := fromIx.Subtree(ou.ID)
	parentPath := toIx.PathTo(in.TargetParentID)
	sourcePath := fromIx.PathTo(ou.ID)
	if parentPath == nil || sourcePath == nil {
		return nil, fmt.Errorf("could not resolve the OU's path in one of the snapshots")
	}

	// Nodes that are new to the target organization: for a cross-org move the
	// whole subtree is recreated, so every OU and account joins fresh.
	fresh := map[string]bool{}
	if crossOrg {
		for _, o := range ous {
			fresh[o.ID] = true
		}
		for _, a := range accounts {
			fresh[a.ID] = true
		}
	}
	ouNode := snapshot.Node{ID: ou.ID, Name: ou.Name, Kind: snapshot.KindOU}
	res := &OUResult{
		Tool: "orgshift", ResultSchemaVersion: ResultSchemaVersion,
		Subject: OUSubject{
			OUID: ou.ID, OUName: ou.Name,
			SourceOrg: OrgRef{ID: in.From.Organization.ID, Name: in.From.Organization.Name},
			TargetOrg: OrgRef{ID: to.Organization.ID, Name: to.Organization.Name},
			CrossOrg:  crossOrg, SourcePath: sourcePath, TargetPath: append(append([]snapshot.Node(nil), parentPath...), ouNode),
			SourceParentID: ou.ParentID, TargetParentID: in.TargetParentID,
			NestedOUs: len(ous) - 1, Accounts: len(accounts),
		},
		Findings: []Finding{}, Accounts: []AccountRollup{}, Attachments: []OUAttachment{},
	}
	if crossOrg {
		res.Subject.TransferMethod = TransferDirect
		if in.TransferMethod != "" {
			res.Subject.TransferMethod = in.TransferMethod
		}
	}
	if !crossOrg && ou.ParentID == in.TargetParentID {
		res.Notes = append(res.Notes, "The target parent is the OU's current parent; the simulation compares the OU with itself.")
	}
	if len(accounts) == 0 {
		res.Notes = append(res.Notes, "The OU contains no accounts; only the OU's own position and attachments were evaluated.")
	}

	// Per-account evaluation. The account keeps its place inside the subtree;
	// only the part of the path above the moved OU changes.
	for _, a := range accounts {
		srcPath := fromIx.PathTo(a.ID)
		var inside []snapshot.Node // nodes from the moved OU down to the account's parent
		for i, n := range srcPath {
			if n.ID == ou.ID {
				inside = srcPath[i : len(srcPath)-1]
				break
			}
		}
		targetPath := append(append([]snapshot.Node(nil), parentPath...), inside...)
		targetPath = append(targetPath, snapshot.Node{ID: a.ID, Name: a.Name, Kind: snapshot.KindAccount})
		r, err := evaluateMove(move{from: in.From, to: to, fromIx: fromIx, toIx: toIx, account: a, targetPath: targetPath, fresh: fresh, method: in.TransferMethod})
		if err != nil {
			return nil, fmt.Errorf("account %s: %w", a.ID, err)
		}
		res.Accounts = append(res.Accounts, rollup(r, inside))
	}
	sort.SliceStable(res.Accounts, func(i, j int) bool {
		if rank(res.Accounts[i].Verdict) != rank(res.Accounts[j].Verdict) {
			return rank(res.Accounts[i].Verdict) > rank(res.Accounts[j].Verdict)
		}
		return res.Accounts[i].AccountName < res.Accounts[j].AccountName
	})

	// The OU's own attachments, and those of nested OUs.
	fate := "carried"
	if crossOrg {
		fate = "recreate"
	}
	for _, o := range ous {
		for _, p := range fromIx.AttachedAll(o.ID) {
			f := fate
			if crossOrg && p.AWSManaged {
				f = "automatic"
			}
			if crossOrg && p.ControlTowerManaged() {
				f = "control-tower"
			}
			res.Attachments = append(res.Attachments, OUAttachment{OUID: o.ID, OUName: o.Name, PolicyID: p.ID, PolicyName: p.Name,
				PolicyType: p.Type.Short(), AWSManaged: p.AWSManaged, ControlTowerManaged: p.ControlTowerManaged(), Fate: f})
		}
	}
	res.Findings = append(res.Findings, ouFindings(in.From, to, ou, ous, accounts, res.Attachments, crossOrg, parentNode)...)
	res.Findings = append(res.Findings, ouControlTowerFindings(in.From, to, ous, crossOrg, parentNode)...)
	if crossOrg {
		res.Notes = append(res.Notes, "Recreated OUs keep their source IDs in this report as placeholders; the target organization assigns new IDs.")
	}

	// Inherited policies at the OU's own position, before and after.
	e := &evaluation{from: in.From, to: to, crossOrg: crossOrg, docs: map[string]parsedDoc{}}
	e.src = side{name: "source", snap: in.From, ix: fromIx, orgID: in.From.Organization.ID, path: sourcePath, fresh: map[string]bool{}}
	e.dst = side{name: "target", snap: to, ix: toIx, orgID: to.Organization.ID, path: res.Subject.TargetPath, fresh: fresh}
	for _, t := range snapshot.AllPolicyTypes {
		res.Diff = append(res.Diff, e.diff(t))
	}

	res.Verdict = StatusGo
	for _, f := range res.Findings {
		res.Verdict = Worst(res.Verdict, f.Status)
	}
	for _, a := range res.Accounts {
		res.Verdict = Worst(res.Verdict, a.Verdict)
	}
	res.Summary = summarizeOU(res)
	return res, nil
}

func rollup(r *Result, inside []snapshot.Node) AccountRollup {
	noGo, review := countFindings(r)
	ar := AccountRollup{AccountID: r.Subject.AccountID, AccountName: r.Subject.AccountName,
		RelativePath: snapshot.PathString(inside), Verdict: r.Verdict, Blocking: noGo, Review: review, Result: r}
	seen := map[string]bool{}
	for _, c := range r.Checks {
		for _, f := range c.Findings {
			if f.Status == StatusInfo {
				ar.Info++
			}
			if f.Status == StatusNoGo && !seen[f.Title] {
				seen[f.Title] = true
				ar.BlockingTitles = append(ar.BlockingTitles, f.Title)
			}
		}
	}
	return ar
}

// ouFindings produces the findings that belong to the OU rather than to any
// one account.
func ouFindings(from, to *snapshot.Snapshot, ou *snapshot.OU, ous []*snapshot.OU, accounts []*snapshot.Account,
	attachments []OUAttachment, crossOrg bool, parent snapshot.Node) []Finding {
	var out []Finding
	byOU := map[string][]string{}
	var ouOrder []string
	for _, at := range attachments {
		if at.AWSManaged || at.ControlTowerManaged {
			continue
		}
		if _, ok := byOU[at.OUID]; !ok {
			ouOrder = append(ouOrder, at.OUID)
		}
		byOU[at.OUID] = append(byOU[at.OUID], at.PolicyType+" "+at.PolicyName)
	}
	nameOf := map[string]string{}
	for _, o := range ous {
		nameOf[o.ID] = o.Name
	}
	var evidence []Evidence
	for _, id := range ouOrder {
		evidence = append(evidence, Evidence{Kind: "ou-attachments", Side: "source", Reference: id,
			Note: fmt.Sprintf("OU %s: %s", nameOf[id], strings.Join(byOU[id], ", "))})
	}
	nested := ""
	if len(ous) > 1 {
		nested = fmt.Sprintf(" and its %d nested OU(s)", len(ous)-1)
	}

	if crossOrg {
		acctIDs := make([]string, 0, len(accounts))
		for _, a := range accounts {
			acctIDs = append(acctIDs, a.ID)
		}
		out = append(out, Finding{Status: StatusReview,
			Title: fmt.Sprintf("OU %s%s cannot move between organizations and must be recreated under %s", ou.Name, nested, parent.Name),
			Detail: fmt.Sprintf("Organizations moves accounts, never OUs, across organizations. Each of the %d account(s) leaves %s on its own, is invited into %s and is then placed into OUs you create by hand under %s (%s). "+
				"%d customer-managed policy attachment(s) on the OU tree do not travel: the policies must be recreated in the target organization and attached to the new OUs, or dropped on purpose. "+
				"The per-account verdicts below assume the recreated OUs start with only the AWS managed defaults attached.",
				len(accounts), from.Organization.ID, to.Organization.ID, parent.Name, parent.ID, len(evidence)),
			Resource: strings.Join(acctIDs, ", "), Evidence: evidence})
		if len(evidence) == 0 {
			out[len(out)-1].Detail = strings.Replace(out[len(out)-1].Detail, "0 customer-managed policy attachment(s) on the OU tree do not travel: the policies must be recreated in the target organization and attached to the new OUs, or dropped on purpose. ",
				"No customer-managed policies are attached on the OU tree, so nothing has to be recreated for the OUs themselves. ", 1)
		}
		return out
	}

	if len(evidence) > 0 {
		out = append(out, Finding{Status: StatusInfo,
			Title:    fmt.Sprintf("Policies attached to %s%s move with it", ou.Name, nested),
			Detail:   "Moving an OU inside the organization keeps every attachment on the OU and on its nested OUs and accounts. Only what is inherited from above the OU changes, which is what the diff below and the per-account verdicts show.",
			Evidence: evidence})
	} else {
		out = append(out, Finding{Status: StatusInfo,
			Title:  fmt.Sprintf("No customer-managed policies are attached to %s%s", ou.Name, nested),
			Detail: "Everything the accounts inherit comes from above the OU, so the move changes their effective policies exactly as the diff below shows."})
	}
	return out
}

func summarizeOU(r *OUResult) string {
	s := r.Subject
	move := fmt.Sprintf("Moving OU %s (%s) with %d account(s) from %s to %s", s.OUName, s.OUID, s.Accounts,
		snapshot.PathString(s.SourcePath[:len(s.SourcePath)-1]), snapshot.PathString(s.TargetPath[:len(s.TargetPath)-1]))
	if s.CrossOrg {
		move += fmt.Sprintf(" (organization %s to %s)", s.SourceOrg.ID, s.TargetOrg.ID)
	}
	counts := map[Status]int{}
	for _, a := range r.Accounts {
		counts[a.Verdict]++
	}
	byVerdict := fmt.Sprintf("%d account(s) NO-GO, %d REVIEW, %d GO", counts[StatusNoGo], counts[StatusReview], counts[StatusGo])
	switch r.Verdict {
	case StatusNoGo:
		return fmt.Sprintf("%s: NO-GO. %s; the OU verdict is the worst account verdict.", move, byVerdict)
	case StatusReview:
		return fmt.Sprintf("%s: REVIEW. %s; nothing blocks the move outright but decisions are needed.", move, byVerdict)
	}
	return fmt.Sprintf("%s: GO. %s.", move, byVerdict)
}

// ouControlTowerFindings flags registered OUs in the moved subtree and a
// registered target parent, which both mean the move has to go through
// Control Tower.
func ouControlTowerFindings(from, to *snapshot.Snapshot, ous []*snapshot.OU, crossOrg bool, parent snapshot.Node) []Finding {
	var out []Finding
	if ct := from.ControlTower; ct != nil {
		var registered []string
		var evidence []Evidence
		for _, o := range ous {
			if r := ct.RegisteredOU(o.ID); r != nil {
				registered = append(registered, o.Name)
				evidence = append(evidence, registrationEvidence("source", snapshot.Node{ID: o.ID, Name: o.Name, Kind: snapshot.KindOU}, r))
			}
		}
		if len(registered) > 0 {
			detail := "Control Tower registers OUs by their identity, so the registration does not follow the OU. Every enrolled account under them is unenrolled while the OU is recreated and stays that way until the new OU is registered and the accounts are re-enrolled through Account Factory. Guardrail SCPs (aws-guardrails-*) are attached again by Control Tower at registration; they do not need to be recreated by hand."
			if !crossOrg {
				detail = "Control Tower expects registered OUs to stay where they were registered. Re-parenting one is not a supported operation: deregister the OU (which unenrolls its accounts), recreate it under the new parent, register it again and re-enroll the accounts through Account Factory. Guardrail SCPs (aws-guardrails-*) are attached again by Control Tower at registration."
			}
			out = append(out, Finding{Status: StatusReview,
				Title:    fmt.Sprintf("%d registered OU(s) in the moved tree have to be deregistered and registered again: %s", len(registered), strings.Join(registered, ", ")),
				Detail:   detail,
				Evidence: evidence})
		}
	}
	if ct := to.ControlTower; ct != nil {
		if r := ct.RegisteredOU(parent.ID); r != nil {
			out = append(out, Finding{Status: StatusInfo,
				Title:    fmt.Sprintf("The new parent %s is registered with Control Tower; register the moved OU too", parent.Name),
				Detail:   "Registration is not inherited. Nested OUs under a registered parent inherit its controls through the SCPs, but Control Tower only governs the accounts in an OU once that OU is registered itself. The per-account findings below list what enrolment needs.",
				Evidence: []Evidence{registrationEvidence("target", parent, r)}})
		}
	}
	return out
}
