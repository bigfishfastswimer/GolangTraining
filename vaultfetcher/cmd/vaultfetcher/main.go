package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v3"

	"github.com/bigfishfastswimer/vault-vars-generator/vaultfetcher/internal/config"
)

type CLI struct {
	ConfigPath    string        `help:"Path to the vault secrets definition file" short:"c" default:"vault_secrets.yaml"`
	BranchName    string        `help:"Branch name used to resolve branch-overrides" short:"b"`
	OutputPath    string        `help:"Destination file for the received secrets" short:"o" default:"vault/vault_received.yaml"`
	MountPath     string        `help:"Vault KV v2 mount path" default:"secrets/sync"`
	PasswordField string        `help:"Field within the Vault secret to read" default:"password"`
	VaultAddr     string        `help:"Vault address" env:"VAULT_ADDR"`
	Token         string        `help:"Vault token" env:"VAULT_TOKEN"`
	Timeout       time.Duration `help:"Maximum duration for a single Vault request" default:"30s"`
	Validate      bool          `help:"Validate configuration and exit without fetching secrets"`
}

func (c *CLI) Run() error {
	cfg, err := config.Load(c.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	branch := resolveBranchName(c.BranchName)

	log.Printf("resolved branch: %q", branch)

	if c.Validate {
		log.Printf("validation successful for %d secret definitions", len(cfg.VaultSecrets))
		return nil
	}

	addr := strings.TrimSpace(c.VaultAddr)
	if addr == "" {
		return fmt.Errorf("VAULT_ADDR environment variable or --vault-addr flag must be provided")
	}

	token := strings.TrimSpace(c.Token)
	if token == "" {
		return fmt.Errorf("VAULT_TOKEN environment variable or --token flag must be provided")
	}

	mount := strings.Trim(strings.TrimSpace(c.MountPath), "/")
	if mount == "" {
		return fmt.Errorf("mount path cannot be empty")
	}

	results := make([]string, 0, len(cfg.VaultSecrets))

	for _, secret := range cfg.VaultSecrets {
		target := secret.TargetForBranch(branch)
		password, err := fetchPassword(context.Background(), addr, token, mount, target, c.PasswordField, c.Timeout)
		if err != nil {
			return fmt.Errorf("fetch secret %q: %w", secret.Name, err)
		}
		results = append(results, fmt.Sprintf("%s=%s", secret.Name, password))
		log.Printf("retrieved secret %q from namespace %q", secret.Name, target.Namespace)
	}

	if err := writeOutput(c.OutputPath, results); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	log.Printf("wrote %d secrets to %s", len(results), c.OutputPath)
	return nil
}

func main() {
	var cli CLI
	kongCtx := kong.Parse(&cli, kong.Name("vaultfetcher"), kong.Description("Retrieve Vault secrets defined in vault_secrets.yaml"))
	if err := cli.Run(); err != nil {
		kongCtx.Fatalf("%v", err)
	}
}

func resolveBranchName(flagValue string) string {
	flagValue = strings.TrimSpace(flagValue)
	if flagValue != "" {
		return flagValue
	}

	envVars := []string{
		"BAMBOO_PLAN_REPOSITORY_BRANCH",
		"BAMBOO_REPO_BRANCH",
		"BAMBOO_BRANCH_NAME",
		"GIT_BRANCH",
		"BRANCH_NAME",
	}

	for _, env := range envVars {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}

	return ""
}

func fetchPassword(ctx context.Context, addr, token, mount string, target config.Target, passwordField string, timeout time.Duration) (string, error) {
	conf := api.DefaultConfig()
	conf.Address = addr

	client, err := api.NewClient(conf)
	if err != nil {
		return "", fmt.Errorf("new client: %w", err)
	}

	client.SetToken(token)
	if strings.TrimSpace(target.Namespace) != "" {
		client.SetNamespace(target.Namespace)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	path := fmt.Sprintf("cyberark/accounts/%s", target.AccountID)
	secret, err := client.KVv2(mount).Get(ctx, path)
	if err != nil {
		return "", fmt.Errorf("read secret at %s (namespace %s): %w", path, target.Namespace, err)
	}

	value, ok := secret.Data[passwordField]
	if !ok {
		return "", fmt.Errorf("field %q missing in secret %s", passwordField, path)
	}

	password, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("field %q in secret %s is not a string", passwordField, path)
	}

	if password == "" {
		return "", errors.New("password value is empty")
	}

	return password, nil
}

func writeOutput(path string, results []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	type output struct {
		Vault []string `yaml:"vault"`
	}

	out := output{Vault: results}

	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}
