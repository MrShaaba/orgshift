package evaluator

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func (e *evaluation) policyRef(p *snapshot.Policy, level string) PolicyRef {
	ref := PolicyRef{ID: p.ID, Name: p.Name, Description: p.Description, AWSManaged: p.AWSManaged, Level: level, Document: p.Document}
	if p.Type == snapshot.PolicyTypeSCP || p.Type == snapshot.PolicyTypeRCP {
		if doc, err := e.parsed(p); err == nil {
			for _, st := range doc.Statements {
				ss := StatementSummary{Sid: st.Sid, Effect: st.Effect, Actions: st.Actions, NotActions: st.NotActions, HasCondition: len(st.Conditions) > 0}
				for _, c := range st.Conditions {
					ss.Conditions = append(ss.Conditions, c.Operator+" "+c.Key+" = "+strings.Join(c.Values, " | "))
				}
				ref.Statements = append(ref.Statements, ss)
			}
		}
	}
	return ref
}

func canonical(doc json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, doc); err != nil {
		return string(doc)
	}
	return buf.String()
}

// diff builds the "what changes" view for one policy type.
func (e *evaluation) diff(t snapshot.PolicyType) Diff {
	d := Diff{Type: string(t), TypeShort: t.Short(), EnabledSource: e.from.PolicyTypeEnabled(t), EnabledTarget: e.to.PolicyTypeEnabled(t)}
	type entry struct {
		ref PolicyRef
		doc string
	}
	collect := func(ch []link) ([]ChainLink, map[string]entry, []string) {
		var links []ChainLink
		byName := map[string]entry{}
		var order []string
		for _, l := range ch {
			cl := ChainLink{Node: l.node}
			for _, p := range l.policies {
				ref := e.policyRef(p, levelLabel(l.node))
				cl.Policies = append(cl.Policies, ref)
				if _, ok := byName[p.Name]; !ok {
					order = append(order, p.Name)
				}
				byName[p.Name] = entry{ref: ref, doc: canonical(p.Document)}
			}
			links = append(links, cl)
		}
		return links, byName, order
	}
	var srcByName, dstByName map[string]entry
	var srcOrder, dstOrder []string
	if d.EnabledSource {
		d.SourceChain, srcByName, srcOrder = collect(e.chain(&e.src, t))
	}
	if d.EnabledTarget {
		d.TargetChain, dstByName, dstOrder = collect(e.chain(&e.dst, t))
	}
	for _, name := range srcOrder {
		s := srcByName[name]
		if dEntry, ok := dstByName[name]; ok {
			if dEntry.doc == s.doc {
				d.Unchanged = append(d.Unchanged, dEntry.ref)
			} else {
				d.Changed = append(d.Changed, dEntry.ref)
			}
		} else {
			d.Removed = append(d.Removed, s.ref)
		}
	}
	for _, name := range dstOrder {
		if _, ok := srcByName[name]; !ok {
			d.Added = append(d.Added, dstByName[name].ref)
		}
	}
	return d
}
