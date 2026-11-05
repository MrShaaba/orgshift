package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Load reads and validates a snapshot file.
func Load(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := Read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Read parses and validates a snapshot from a reader.
func Read(r io.Reader) (*Snapshot, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses and validates a snapshot from JSON bytes. Documents written
// with an older schema version are upgraded in memory; see Upgrade.
func Parse(data []byte) (*Snapshot, error) {
	var head struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, fmt.Errorf("not a snapshot: %w", err)
	}
	if head.SchemaVersion == 0 {
		return nil, fmt.Errorf("not a snapshot: schema_version is missing")
	}
	if head.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("snapshot schema version %d is newer than this build supports (%d)", head.SchemaVersion, SchemaVersion)
	}
	if head.SchemaVersion < 1 {
		return nil, fmt.Errorf("snapshot schema version %d is not supported", head.SchemaVersion)
	}
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("invalid snapshot: %w", err)
	}
	s.Upgrade()
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Upgrade brings a snapshot written with an older schema version to the
// current one and records the original version in UpgradedFrom. Version 1
// had no coverage block; the upgraded snapshot keeps Coverage nil, which
// the evaluator reports as unknown coverage. Version 2 had no workload
// inventory; the upgraded snapshot has no workloads block and no records
// for the workloads.* domains, which read as unknown even under a
// completeness assertion, because the assertion predates them.
func (s *Snapshot) Upgrade() {
	if s.SchemaVersion >= SchemaVersion {
		return
	}
	s.UpgradedFrom = s.SchemaVersion
	s.SchemaVersion = SchemaVersion
}

// Save writes the snapshot as indented JSON.
func Save(path string, s *Snapshot) error {
	data, err := Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Marshal renders the snapshot as indented JSON with a trailing newline.
func Marshal(s *Snapshot) ([]byte, error) {
	if s.SchemaVersion == 0 {
		s.SchemaVersion = SchemaVersion
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
