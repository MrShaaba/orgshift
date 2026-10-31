// Package usage loads "actions in use" lists from hand-written files and
// from IAM last-accessed exports.
package usage

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// LoadActionsFile reads a JSON file that is either an array of action
// strings, an array of ActionInUse objects, or an object with an "actions"
// field holding one of those.
func LoadActionsFile(path string) ([]snapshot.ActionInUse, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	acts, err := ParseActions(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return acts, nil
}

// ParseActions parses the formats accepted by LoadActionsFile.
func ParseActions(data []byte) ([]snapshot.ActionInUse, error) {
	var wrapper struct {
		Actions json.RawMessage `json:"actions"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Actions) > 0 {
		data = wrapper.Actions
	}
	var strs []string
	if err := json.Unmarshal(data, &strs); err == nil {
		out := make([]snapshot.ActionInUse, 0, len(strs))
		for _, s := range strs {
			if err := validAction(s); err != nil {
				return nil, err
			}
			out = append(out, snapshot.ActionInUse{Action: s, Source: "manual"})
		}
		return out, nil
	}
	var acts []snapshot.ActionInUse
	if err := json.Unmarshal(data, &acts); err != nil {
		return nil, fmt.Errorf("expected an array of action strings or action objects: %w", err)
	}
	for i := range acts {
		if err := validAction(acts[i].Action); err != nil {
			return nil, err
		}
		if acts[i].Source == "" {
			acts[i].Source = "manual"
		}
	}
	return acts, nil
}

func validAction(s string) error {
	if !strings.Contains(s, ":") || strings.HasPrefix(s, ":") {
		return fmt.Errorf("action %q must look like service:Action", s)
	}
	return nil
}

// lastAccessedExport mirrors the fields of
// `aws iam get-service-last-accessed-details` that matter here.
type lastAccessedExport struct {
	JobStatus            string `json:"JobStatus"`
	JobType              string `json:"JobType"`
	ServicesLastAccessed []struct {
		ServiceName                string `json:"ServiceName"`
		ServiceNamespace           string `json:"ServiceNamespace"`
		LastAuthenticated          string `json:"LastAuthenticated"`
		LastAuthenticatedRegion    string `json:"LastAuthenticatedRegion"`
		TrackedActionsLastAccessed []struct {
			ActionName         string `json:"ActionName"`
			LastAccessedTime   string `json:"LastAccessedTime"`
			LastAccessedRegion string `json:"LastAccessedRegion"`
		} `json:"TrackedActionsLastAccessed"`
	} `json:"ServicesLastAccessed"`
}

// LoadLastAccessed converts an IAM last-accessed export into actions in use.
func LoadLastAccessed(path string) ([]snapshot.ActionInUse, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	acts, err := ParseLastAccessed(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return acts, nil
}

// ParseLastAccessed converts the JSON of an IAM last-accessed export.
// Services that were never authenticated are skipped. Services with tracked
// actions yield one entry per action; the rest yield "service:*". Regions
// are recorded as notes only, because the export only remembers the most
// recent region, not every region the action is used in.
func ParseLastAccessed(data []byte) ([]snapshot.ActionInUse, error) {
	var exp lastAccessedExport
	if err := json.Unmarshal(data, &exp); err != nil {
		return nil, fmt.Errorf("not an IAM last-accessed export: %w", err)
	}
	if len(exp.ServicesLastAccessed) == 0 {
		return nil, fmt.Errorf("export has no ServicesLastAccessed entries (job status %q)", exp.JobStatus)
	}
	var out []snapshot.ActionInUse
	for _, svc := range exp.ServicesLastAccessed {
		if svc.LastAuthenticated == "" {
			continue
		}
		if len(svc.TrackedActionsLastAccessed) == 0 {
			out = append(out, snapshot.ActionInUse{
				Action: svc.ServiceNamespace + ":*", Source: "iam-last-accessed", LastUsed: svc.LastAuthenticated,
				Note: fmt.Sprintf("%s used (last region %s); IAM does not track individual actions for this service", svc.ServiceName, orUnknown(svc.LastAuthenticatedRegion)),
			})
			continue
		}
		for _, a := range svc.TrackedActionsLastAccessed {
			if a.LastAccessedTime == "" {
				continue
			}
			name := a.ActionName
			if !strings.Contains(name, ":") {
				name = svc.ServiceNamespace + ":" + name
			}
			out = append(out, snapshot.ActionInUse{
				Action: name, Source: "iam-last-accessed", LastUsed: a.LastAccessedTime,
				Note: "last region " + orUnknown(a.LastAccessedRegion),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Action < out[j].Action })
	return out, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Merge adds actions to an existing list, replacing entries with the same
// action name.
func Merge(existing, added []snapshot.ActionInUse) []snapshot.ActionInUse {
	idx := map[string]int{}
	out := append([]snapshot.ActionInUse(nil), existing...)
	for i, a := range out {
		idx[strings.ToLower(a.Action)] = i
	}
	for _, a := range added {
		if i, ok := idx[strings.ToLower(a.Action)]; ok {
			out[i] = a
			continue
		}
		idx[strings.ToLower(a.Action)] = len(out)
		out = append(out, a)
	}
	return out
}
