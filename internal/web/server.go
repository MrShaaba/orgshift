// Package web serves the orgshift UI: server-rendered HTML with HTMX, no
// build step, everything embedded in the binary.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/report"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

const maxUpload = 32 << 20

// Server is the HTTP handler for the UI.
type Server struct {
	store *Store
	tmpl  *template.Template
	log   *log.Logger
}

// New builds a server around a store.
func New(store *Store, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.Default()
	}
	funcs := template.FuncMap{
		"statusClass": statusClass,
		"pretty":      prettyJSON,
		"count":       countStatus,
		"pathLabel":   pathLabel,
		"parentPath":  parentPath,
		"plural":      plural,
		"join":        strings.Join,
		"lower":       strings.ToLower,
		"sortedKeys":  sortedKeys,
		"firstN":      firstN,
		"leftOver":    leftOver,
		"dict":        dict,
		"stepNumber":  stepNumber,
		"inc":         func(i int) int { return i + 1 },
		"doneKey":     doneKey,
		"lines":       func(list []string) string { return strings.Join(list, "\n") },
		"coverClass":  coverageClass,
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{store: store, tmpl: tmpl, log: logger}, nil
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("POST /snapshots", s.handleUpload)
	mux.HandleFunc("POST /snapshots/fixtures", s.handleFixtures)
	mux.HandleFunc("GET /partials/accounts", s.handleAccounts)
	mux.HandleFunc("GET /partials/subject", s.handleSubject)
	mux.HandleFunc("GET /partials/ous", s.handleOUs)
	mux.HandleFunc("GET /simulate", s.handleSimulate)
	mux.HandleFunc("POST /simulate", s.handleSimulate)
	mux.HandleFunc("GET /export.json", s.handleExport)
	mux.HandleFunc("GET /export.md", s.handleExport)
	mux.HandleFunc("GET /runbook.md", s.handleExport)
	mux.HandleFunc("GET /runbook.json", s.handleExport)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	return s.logging(mux)
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

type pageData struct {
	Snapshots []snapshotOption
	Form      formValues
	Result    *resultView
	OUResult  *ouResultView
	Error     string
	Flash     string
}

type snapshotOption struct {
	Name     string
	OrgID    string
	Accounts int
	Source   string
}

type formValues struct {
	From, To, Account, TargetOU string
	// Kind is "account" or "ou"; OU is the subject OU when Kind is "ou".
	Kind, OU string
}

func (s *Server) options() []snapshotOption {
	var out []snapshotOption
	for _, n := range s.store.Names() {
		snap, _ := s.store.Get(n)
		out = append(out, snapshotOption{Name: n, OrgID: snap.Organization.ID, Accounts: len(snap.Accounts), Source: snap.Source})
	}
	return out
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Printf("template %s: %v", name, err)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data := pageData{Snapshots: s.options(), Flash: r.URL.Query().Get("flash"), Error: r.URL.Query().Get("error"), Form: formValues{Kind: "account"}}
	names := s.store.Names()
	if len(names) > 0 {
		data.Form.From = names[0]
		data.Form.To = names[len(names)-1]
	}
	s.render(w, "index.html", data)
}

func (s *Server) handleFixtures(w http.ResponseWriter, r *http.Request) {
	s.store.LoadFixtures()
	http.Redirect(w, r, "/?flash="+url.QueryEscape("Loaded the Larkspur Holdings and Fernhill Group fixtures."), http.StatusSeeOther)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		http.Redirect(w, r, "/?error="+url.QueryEscape("upload failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	var loaded []string
	for _, field := range []string{"source", "target"} {
		f, hdr, err := r.FormFile(field)
		if err != nil {
			continue
		}
		snap, err := snapshot.Read(f)
		f.Close()
		if err != nil {
			http.Redirect(w, r, "/?error="+url.QueryEscape(hdr.Filename+": "+err.Error()), http.StatusSeeOther)
			return
		}
		name := snap.Organization.Name
		if name == "" {
			name = strings.TrimSuffix(hdr.Filename, ".json")
		}
		loaded = append(loaded, s.store.Add(name, snap))
	}
	if len(loaded) == 0 {
		http.Redirect(w, r, "/?error="+url.QueryEscape("choose at least one snapshot file"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?flash="+url.QueryEscape("Loaded "+strings.Join(loaded, " and ")+"."), http.StatusSeeOther)
}

type optionGroup struct {
	Label   string
	Options []option
}

type option struct {
	Value, Label string
	Depth        int
	Selected     bool
}

// handleSubject renders the subject picker for the chosen kind: the accounts
// of the source snapshot grouped by OU, or its OUs.
func (s *Server) handleSubject(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("kind") == "ou" {
		s.handleSubjectOUs(w, r)
		return
	}
	s.handleAccounts(w, r)
}

func (s *Server) handleSubjectOUs(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.store.Get(r.URL.Query().Get("from"))
	if !ok {
		s.render(w, "select_subject_ous.html", nil)
		return
	}
	selected := r.URL.Query().Get("ou")
	if selected == "" {
		selected = r.URL.Query().Get("ou_preselect")
	}
	ix := snap.Index()
	var opts []option
	var walk func(id string, depth int)
	walk = func(id string, depth int) {
		for _, ou := range ix.ChildOUs(id) {
			_, accts := ix.Subtree(ou.ID)
			opts = append(opts, option{Value: ou.ID, Label: fmt.Sprintf("%s%s (%s) · %s", strings.Repeat("   ", depth), ou.Name, ou.ID, plural(len(accts), "account", "accounts")), Depth: depth, Selected: ou.ID == selected})
			walk(ou.ID, depth+1)
		}
	}
	walk(snap.Root.ID, 0)
	s.render(w, "select_subject_ous.html", opts)
}

func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.store.Get(r.URL.Query().Get("from"))
	if !ok {
		s.render(w, "select_accounts.html", nil)
		return
	}
	selected := r.URL.Query().Get("account")
	if selected == "" {
		selected = r.URL.Query().Get("account_preselect")
	}
	ix := snap.Index()
	var groups []optionGroup
	var walk func(parent snapshot.Node, path string)
	walk = func(parent snapshot.Node, path string) {
		accts := ix.AccountsIn(parent.ID)
		if len(accts) > 0 {
			g := optionGroup{Label: path}
			for _, a := range accts {
				g.Options = append(g.Options, option{Value: a.ID, Label: a.Name + " (" + a.ID + ")", Selected: a.ID == selected})
			}
			groups = append(groups, g)
		}
		for _, ou := range ix.ChildOUs(parent.ID) {
			walk(snapshot.Node{ID: ou.ID, Name: ou.Name, Kind: snapshot.KindOU}, path+" / "+ou.Name)
		}
	}
	walk(snapshot.Node{ID: snap.Root.ID, Name: snap.Root.Name, Kind: snapshot.KindRoot}, snap.Root.Name)
	s.render(w, "select_accounts.html", groups)
}

func (s *Server) handleOUs(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.store.Get(r.URL.Query().Get("to"))
	if !ok {
		s.render(w, "select_ous.html", nil)
		return
	}
	selected := r.URL.Query().Get("target_ou")
	if selected == "" {
		selected = r.URL.Query().Get("target_ou_preselect")
	}
	ix := snap.Index()
	var opts []option
	var walk func(id, name string, depth int)
	walk = func(id, name string, depth int) {
		opts = append(opts, option{Value: id, Label: strings.Repeat("   ", depth) + name + " (" + id + ")", Depth: depth, Selected: id == selected})
		for _, ou := range ix.ChildOUs(id) {
			walk(ou.ID, ou.Name, depth+1)
		}
	}
	walk(snap.Root.ID, snap.Root.Name, 0)
	s.render(w, "select_ous.html", opts)
}

// simulation is the outcome of one request: exactly one of Account or OU is set.
type simulation struct {
	Account *resultView
	OU      *ouResultView
	Query   string
}

// simulate runs the evaluation for a request's parameters.
func (s *Server) simulate(r *http.Request) (*simulation, formValues, error) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, formValues{}, err
		}
	}
	fv := formValues{From: r.FormValue("from"), To: r.FormValue("to"), Account: r.FormValue("account"), TargetOU: r.FormValue("target_ou"),
		Kind: r.FormValue("kind"), OU: r.FormValue("ou")}
	if fv.Kind == "" {
		fv.Kind = "account"
		if fv.Account == "" && fv.OU != "" {
			fv.Kind = "ou"
		}
	}
	if fv.Kind != "account" && fv.Kind != "ou" {
		return nil, fv, fmt.Errorf("kind must be account or ou, not %q", fv.Kind)
	}
	from, ok := s.store.Get(fv.From)
	if !ok {
		return nil, fv, fmt.Errorf("source snapshot %q is not loaded", fv.From)
	}
	toName := fv.To
	if toName == "" {
		toName = fv.From
	}
	to, ok := s.store.Get(toName)
	if !ok {
		return nil, fv, fmt.Errorf("target snapshot %q is not loaded", toName)
	}
	if fv.Kind == "ou" {
		res, err := evaluator.EvaluateOU(evaluator.OUInput{From: from, To: to, OUID: fv.OU, TargetParentID: fv.TargetOU})
		if err != nil {
			return nil, fv, err
		}
		q := url.Values{"kind": {"ou"}, "from": {fv.From}, "to": {toName}, "ou": {fv.OU}, "target_ou": {fv.TargetOU}}
		return &simulation{OU: newOUResultView(res, fv.From, toName, from, to, q.Encode()), Query: q.Encode()}, fv, nil
	}
	res, err := evaluator.Evaluate(evaluator.Input{From: from, To: to, AccountID: fv.Account, TargetOUID: fv.TargetOU})
	if err != nil {
		return nil, fv, err
	}
	q := url.Values{"from": {fv.From}, "to": {toName}, "account": {fv.Account}, "target_ou": {fv.TargetOU}}
	return &simulation{Account: newResultView(res, fv.From, toName, from, to, q.Encode()), Query: q.Encode()}, fv, nil
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	sim, fv, err := s.simulate(r)
	htmx := r.Header.Get("HX-Request") == "true"
	if err != nil {
		if htmx {
			w.WriteHeader(http.StatusUnprocessableEntity)
			s.render(w, "error.html", err.Error())
			return
		}
		s.render(w, "index.html", pageData{Snapshots: s.options(), Form: fv, Error: err.Error()})
		return
	}
	if htmx {
		w.Header().Set("HX-Push-Url", "/simulate?"+sim.Query)
		if sim.OU != nil {
			s.render(w, "result_ou.html", sim.OU)
		} else {
			s.render(w, "result.html", sim.Account)
		}
		return
	}
	s.render(w, "index.html", pageData{Snapshots: s.options(), Form: fv, Result: sim.Account, OUResult: sim.OU})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	sim, _, err := s.simulate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var (
		base     string
		data     []byte
		markdown string
	)
	isRunbook := strings.HasPrefix(r.URL.Path, "/runbook.")
	switch {
	case sim.OU != nil && isRunbook:
		rb := sim.OU.Runbook
		base = fmt.Sprintf("orgshift-runbook-ou-%s-to-%s", rb.Subject.OUID, rb.Subject.TargetParentID)
		data, err = report.OURunbookJSON(rb)
		markdown = report.OURunbookMarkdown(rb)
	case sim.OU != nil:
		res := sim.OU.Result
		base = fmt.Sprintf("orgshift-ou-%s-to-%s", res.Subject.OUID, res.Subject.TargetParentID)
		data, err = report.OUJSON(res)
		markdown = report.OUMarkdown(res)
	case isRunbook:
		rb := sim.Account.Runbook
		base = fmt.Sprintf("orgshift-runbook-%s-to-%s", rb.Subject.AccountID, rb.Subject.TargetOUID)
		data, err = report.RunbookJSON(rb)
		markdown = report.RunbookMarkdown(rb)
	default:
		res := sim.Account.Result
		base = fmt.Sprintf("orgshift-%s-to-%s", res.Subject.AccountID, res.Subject.TargetOUID)
		data, err = report.JSON(res)
		markdown = report.Markdown(res)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.HasSuffix(r.URL.Path, ".json") {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+base+`.json"`)
		w.Write(data)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+base+`.md"`)
	fmt.Fprint(w, markdown)
}

// sortedKeys is used by templates that need deterministic map iteration.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
