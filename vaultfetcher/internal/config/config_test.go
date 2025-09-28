package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidFile(t *testing.T) {
	t.Helper()

	contents := `vault_secrets:
  - name: artifactoryPassword
    default:
      vault:
        account_id: GA00016094
        namespace: APS00376-non
  - name: iiq_console_password
    default:
      vault:
        account_id: GA03000912
        namespace: AP668493612630IG-NON
    branch-overrides:
      - name: iiq-develop
        vault:
          account_id: GA00300812
          namepsace: AP6649361230IG-NON
`

	dir := t.TempDir()
	path := filepath.Join(dir, "vault_secrets.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got, want := len(cfg.VaultSecrets), 2; got != want {
		t.Fatalf("expected %d secrets, got %d", want, got)
	}

	if got := cfg.VaultSecrets[1].BranchOverrides[0].Vault.Namespace; got != "AP6649361230IG-NON" {
		t.Fatalf("expected namespace to be normalised, got %q", got)
	}
}

func TestValidateReportsIssues(t *testing.T) {
	cfg := &File{VaultSecrets: []Secret{{}}}
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error")
	}

	var vErr *ValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("expected ValidationError, got %T", err)
	}

	if len(vErr.Issues) == 0 {
		t.Fatalf("expected issues to be populated")
	}
}

func TestTargetForBranch(t *testing.T) {
	secret := Secret{
		Name:    "example",
		Default: TargetWrapper{Vault: Target{AccountID: "default", Namespace: "ns-default"}},
		BranchOverrides: []BranchOverride{
			{Name: "refs/heads/feature", Vault: Target{AccountID: "override", Namespace: "ns-override"}},
		},
	}

	target := secret.TargetForBranch("feature")
	if target.AccountID != "override" {
		t.Fatalf("expected override target, got %q", target.AccountID)
	}

	target = secret.TargetForBranch("refs/heads/feature")
	if target.AccountID != "override" {
		t.Fatalf("expected override for full ref, got %q", target.AccountID)
	}

	target = secret.TargetForBranch("main")
	if target.AccountID != "default" {
		t.Fatalf("expected default target, got %q", target.AccountID)
	}
}
