package auditcontrol

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func helperHost(t *testing.T) Helper {
	t.Helper()
	h := Helper{Root: t.TempDir()}
	for _, p := range []string{FlagPath, RulePath, StatusPath} {
		if err := os.MkdirAll(filepath.Dir(h.path(p)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func TestFixedRuleLifecycle(t *testing.T) {
	h := helperHost(t)
	unrelated := filepath.Join(filepath.Dir(h.path(RulePath)), "customer.rules")
	if err := os.WriteFile(unrelated, []byte("customer policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	var loads []string
	deletions := 0
	h.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "auditctl" {
			t.Fatalf("unexpected executable %s", name)
		}
		if slices.Equal(args, []string{"-s"}) {
			return []byte("enabled 1\npid 512\n"), nil
		}
		if slices.Equal(args, []string{"-D", "-k", "oka_cyber_commands"}) {
			deletions++
			return nil, nil
		}
		if !slices.Equal(args, []string{"-R", RulePath}) {
			t.Fatalf("unexpected arguments %q", args)
		}
		b, err := os.ReadFile(h.path(RulePath))
		if err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(h.path(RulePath))
		if info.Mode().Perm() != 0o600 {
			t.Fatal("rules must be private for auditctl -R")
		}
		loads = append(loads, string(b))
		return nil, nil
	}
	for _, on := range []bool{true, true, false, false} {
		if on {
			if err := os.WriteFile(h.path(FlagPath), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		} else {
			_ = os.Remove(h.path(FlagPath))
		}
		if err := h.Apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(h.path(StatusPath))
		want := "off\n"
		if on {
			want = "on\n"
		}
		if string(b) != want {
			t.Fatalf("status %s, want %s", b, want)
		}
		_, err := os.Stat(h.path(RulePath))
		if on && err != nil || !on && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rule exists after on=%v: %v", on, err)
		}
	}
	if len(loads) != 2 || loads[0] != string(rules) || loads[1] != string(rules) || deletions != 4 {
		t.Fatalf("loads = %q, deletions = %d", loads, deletions)
	}
	if strings.Contains(string(rules), "-D") {
		t.Fatal("persistent rule template overrides augenrules deletion policy")
	}

	b, _ := os.ReadFile(unrelated)
	if string(b) != "customer policy" {
		t.Fatal("unrelated rules changed")
	}
}

func TestHelperReportsFailuresAndRejectsFlagContent(t *testing.T) {
	for _, tc := range []struct {
		name, flag, status, want string
		fail                     bool
	}{
		{name: "auditd absent", status: "enabled 1\npid 0\n", want: "auditd_missing"},
		{name: "control unavailable", status: "", want: "audit_control_unavailable"},
		{name: "immutable policy", status: "enabled 2\npid 123\n", want: "rule_apply_failed", fail: true},
		{name: "no rule input accepted", flag: "-D\n-e 0\n", status: "enabled 1\npid 123\n", want: "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := helperHost(t)
			if err := os.WriteFile(h.path(FlagPath), []byte(tc.flag), 0o600); err != nil {
				t.Fatal(err)
			}
			h.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[0] == "-s" {
					if tc.status == "" {
						return nil, errors.New("unavailable")
					}
					return []byte(tc.status), nil
				}
				b, _ := os.ReadFile(h.path(RulePath))
				if strings.Contains(string(b), "-e 0") {
					t.Fatal("untrusted text reached rules")
				}
				if tc.fail {
					return nil, errors.New("locked")
				}
				return nil, nil
			}
			if err := h.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(h.path(StatusPath))
			if strings.TrimSpace(string(b)) != tc.want {
				t.Fatalf("status = %s", b)
			}
		})
	}
}

func TestHelperNeverFollowsFlagOrRuleSymlinks(t *testing.T) {
	h := helperHost(t)
	target := filepath.Join(h.Root, "do-not-touch")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, h.path(FlagPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, h.path(RulePath)); err != nil {
		t.Fatal(err)
	}
	h.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "-s" {
			return []byte("pid 1\n"), nil
		}
		if !slices.Equal(args, []string{"-D", "-k", "oka_cyber_commands"}) {
			t.Fatal("symlink enabled capture")
		}
		return nil, nil
	}
	if err := h.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(target)
	if info.Size() != 0 {
		t.Fatal("followed rule symlink")
	}
}

func TestCleanupFailsWhenKernelRemovalCannotBeConfirmed(t *testing.T) {
	h := helperHost(t)
	if err := os.WriteFile(h.path(RulePath), rules, 0o600); err != nil {
		t.Fatal(err)
	}
	h.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("locked") }
	if err := h.Cleanup(context.Background()); err == nil {
		t.Fatal("claimed the kernel rule was removed")
	}
	if _, err := os.Stat(h.path(RulePath)); !os.IsNotExist(err) {
		t.Fatal("persistent rule survived removal")
	}
	h.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	if err := h.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestMissingAuditToolsAndDisabledAuditAreReported(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		h := helperHost(t)
		if err := os.WriteFile(h.path(FlagPath), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		h.Run = func(context.Context, string, ...string) ([]byte, error) {
			if disabled {
				return []byte("enabled 0\npid 123\n"), nil
			}
			return nil, exec.ErrNotFound
		}
		if err := h.Apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		want := "auditd_missing\n"
		if disabled {
			want = "audit_disabled\n"
		}
		b, _ := os.ReadFile(h.path(StatusPath))
		if string(b) != want {
			t.Fatalf("status=%s", b)
		}
	}
}
