package baseline

import (
	"encoding/json"
	"fmt"
	"os"
)

const SchemaVersion = "v0.1"

type Template struct {
	SchemaVersion string      `json:"schema_version"`
	Checks        []FileCheck `json:"checks"`
}

type FileCheck struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	MustExist bool   `json:"must_exist"`
	MaxMode   string `json:"max_mode,omitempty"`
}

type Finding struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Passed   bool   `json:"passed"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

func Load(path string) (Template, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Template{}, err
	}
	var t Template
	if err := json.Unmarshal(raw, &t); err != nil {
		return Template{}, err
	}
	if t.SchemaVersion != SchemaVersion {
		return Template{}, fmt.Errorf("unsupported schema_version %q", t.SchemaVersion)
	}
	return t, nil
}

func Run(t Template) []Finding {
	findings := make([]Finding, 0, len(t.Checks))
	for _, c := range t.Checks {
		st, err := os.Stat(c.Path)
		if err != nil {
			findings = append(findings, Finding{ID: c.ID, Path: c.Path, Passed: !c.MustExist, Expected: "exists", Actual: err.Error()})
			continue
		}
		passed := true
		expected := "exists"
		actual := st.Mode().Perm().String()
		if c.MaxMode != "" {
			var max os.FileMode
			if _, err := fmt.Sscanf(c.MaxMode, "%o", &max); err != nil {
				passed = false
				expected = "valid max_mode"
				actual = c.MaxMode
			} else if st.Mode().Perm()&^max != 0 {
				passed = false
				expected = "mode <= " + c.MaxMode
			}
		}
		findings = append(findings, Finding{ID: c.ID, Path: c.Path, Passed: passed, Expected: expected, Actual: actual})
	}
	return findings
}
