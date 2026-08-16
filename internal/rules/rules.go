// Package rules loads YAML detection-rule configs and compiles them into
// detect rules. See configs/rules.example.yaml for the schema.
package rules

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Arman-Chaudhury/siemlet/internal/detect"
	"github.com/Arman-Chaudhury/siemlet/internal/parse"
)

//go:embed default.yaml
var defaultYAML []byte

type stageSpec struct {
	Kinds     []string `yaml:"kinds"`
	Threshold int      `yaml:"threshold"`
	Window    string   `yaml:"window"`
}

type ruleSpec struct {
	Name         string      `yaml:"name"`
	Kinds        []string    `yaml:"kinds"`
	Key          string      `yaml:"key"`
	Distinct     string      `yaml:"distinct"`
	Threshold    int         `yaml:"threshold"`
	Window       string      `yaml:"window"`
	User         string      `yaml:"user"`
	OutsideHours string      `yaml:"outside_hours"`
	Sequence     []stageSpec `yaml:"sequence"`
}

type fileSpec struct {
	Rules []ruleSpec `yaml:"rules"`
}

// Load reads and compiles a YAML rule file.
func Load(path string) ([]detect.Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rs, err := Compile(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rs, nil
}

// Default returns the stock rule set embedded in the binary.
func Default() []detect.Rule {
	rs, err := Compile(defaultYAML)
	if err != nil {
		panic("embedded default.yaml is invalid: " + err.Error())
	}
	return rs
}

// Compile parses YAML rule config bytes into detect rules.
func Compile(raw []byte) ([]detect.Rule, error) {
	var f fileSpec
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if len(f.Rules) == 0 {
		return nil, errors.New("no rules defined")
	}
	out := make([]detect.Rule, 0, len(f.Rules))
	names := make(map[string]bool, len(f.Rules))
	for i, spec := range f.Rules {
		r, err := compile(spec)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%q): %w", i+1, spec.Name, err)
		}
		if names[r.Name()] {
			return nil, fmt.Errorf("duplicate rule name %q", r.Name())
		}
		names[r.Name()] = true
		out = append(out, r)
	}
	return out, nil
}

var kindNames = map[string]parse.Kind{
	"auth_fail":    parse.AuthFail,
	"auth_success": parse.AuthSuccess,
	"invalid_user": parse.InvalidUser,
	"sudo_command": parse.SudoCommand,
	"user_added":   parse.UserAdded,
	"other":        parse.Other,
}

func compile(s ruleSpec) (detect.Rule, error) {
	if s.Name == "" {
		return nil, errors.New("missing name")
	}
	key, err := field(s.Key, detect.FieldHost)
	if err != nil {
		return nil, err
	}

	if len(s.Sequence) > 0 {
		if s.Kinds != nil || s.Distinct != "" || s.Threshold != 0 || s.Window != "" ||
			s.User != "" || s.OutsideHours != "" {
			return nil, errors.New("sequence rules take only name, key, and sequence")
		}
		if len(s.Sequence) != 2 {
			return nil, fmt.Errorf("sequence must have exactly 2 stages, got %d", len(s.Sequence))
		}
		pre, trig := s.Sequence[0], s.Sequence[1]
		preKinds, err := kinds(pre.Kinds)
		if err != nil {
			return nil, err
		}
		if pre.Threshold < 1 {
			return nil, errors.New("first sequence stage needs threshold >= 1")
		}
		window, err := window(pre.Window, pre.Threshold)
		if err != nil {
			return nil, err
		}
		trigKinds, err := kinds(trig.Kinds)
		if err != nil {
			return nil, err
		}
		if trig.Threshold != 0 || trig.Window != "" {
			return nil, errors.New("second sequence stage takes only kinds")
		}
		return &detect.SequenceRule{
			RuleName:     s.Name,
			PreKinds:     preKinds,
			PreThreshold: pre.Threshold,
			Window:       window,
			TriggerKinds: trigKinds,
			Key:          key,
		}, nil
	}

	ks, err := kinds(s.Kinds)
	if err != nil {
		return nil, err
	}
	if s.Threshold < 1 {
		return nil, errors.New("threshold must be >= 1")
	}
	win, err := window(s.Window, s.Threshold)
	if err != nil {
		return nil, err
	}
	distinct, err := field(s.Distinct, detect.FieldNone)
	if err != nil {
		return nil, err
	}
	var outside *detect.HourRange
	if s.OutsideHours != "" {
		hr, err := detect.ParseHourRange(s.OutsideHours)
		if err != nil {
			return nil, err
		}
		outside = &hr
	}
	return &detect.WindowRule{
		RuleName:  s.Name,
		Kinds:     ks,
		Key:       key,
		Distinct:  distinct,
		Threshold: s.Threshold,
		Window:    win,
		User:      s.User,
		Outside:   outside,
	}, nil
}

func kinds(names []string) (map[parse.Kind]bool, error) {
	if len(names) == 0 {
		return nil, errors.New("missing kinds")
	}
	out := make(map[parse.Kind]bool, len(names))
	for _, n := range names {
		k, ok := kindNames[n]
		if !ok {
			return nil, fmt.Errorf("unknown event kind %q", n)
		}
		out[k] = true
	}
	return out, nil
}

func field(name string, fallback detect.Field) (detect.Field, error) {
	switch name {
	case "":
		return fallback, nil
	case "ip":
		return detect.FieldIP, nil
	case "user":
		return detect.FieldUser, nil
	case "host":
		return detect.FieldHost, nil
	}
	return detect.FieldNone, fmt.Errorf("unknown field %q (want ip, user, or host)", name)
}

// window parses a duration; threshold-1 rules fire on every matching event,
// so their window is irrelevant and may be omitted.
func window(s string, threshold int) (time.Duration, error) {
	if s == "" {
		if threshold > 1 {
			return 0, errors.New("threshold > 1 requires a window")
		}
		return time.Second, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("bad window %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("window must be positive, got %q", s)
	}
	return d, nil
}
