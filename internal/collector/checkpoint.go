package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// CheckpointSchemaVersion is bumped when the checkpoint file shape changes.
const CheckpointSchemaVersion = 1

// Checkpoint is the state of a collection run saved after every completed
// step, so a rerun restores the completed domains and only reads the ones
// that failed or were never reached. A step counts as completed when every
// coverage record it wrote is observed or empty; denied, partial, skipped
// and failed steps are run again.
//
// The file holds the snapshot in progress, so it carries the same data as a
// snapshot (no credentials) and is ignored by git like one.
type Checkpoint struct {
	SchemaVersion int `json:"schema_version"`
	// CollectorVersion is the build that wrote it; a different build does
	// not resume from it.
	CollectorVersion string `json:"collector_version"`
	WrittenAt        string `json:"written_at"`
	// OrganizationID and Region identify the run; a checkpoint for another
	// organization or region is refused.
	OrganizationID string `json:"organization_id"`
	Region         string `json:"region"`
	// Completed lists the step names whose domains were completely read.
	Completed []string           `json:"completed"`
	Snapshot  *snapshot.Snapshot `json:"snapshot"`
}

// LoadCheckpoint reads a checkpoint file. A missing file is reported with
// os.ErrNotExist.
func LoadCheckpoint(path string) (*Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Checkpoint
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("checkpoint %s: %w", path, err)
	}
	if c.SchemaVersion != CheckpointSchemaVersion {
		return nil, fmt.Errorf("checkpoint %s: schema version %d is not %d", path, c.SchemaVersion, CheckpointSchemaVersion)
	}
	if c.Snapshot == nil {
		return nil, fmt.Errorf("checkpoint %s: no snapshot", path)
	}
	return &c, nil
}

// Save writes the checkpoint atomically (temporary file, then rename).
func (c *Checkpoint) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".orgshift-checkpoint-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// usable says whether a checkpoint may be resumed by this run, or why not.
func (c *Checkpoint) usable(version, region string, maxAge time.Duration, now time.Time) error {
	if c.CollectorVersion != version {
		return fmt.Errorf("written by %q, this build is %q", c.CollectorVersion, version)
	}
	if c.Region != region {
		return fmt.Errorf("written for region %s, this run uses %s", c.Region, region)
	}
	at, err := time.Parse(time.RFC3339, c.WrittenAt)
	if err != nil {
		return errors.New("written_at is not RFC 3339")
	}
	if maxAge > 0 && now.Sub(at) > maxAge {
		return fmt.Errorf("written %s ago, older than %s", now.Sub(at).Round(time.Minute), maxAge)
	}
	return nil
}

func (c *Checkpoint) completed(step string) bool {
	for _, s := range c.Completed {
		if s == step {
			return true
		}
	}
	return false
}
