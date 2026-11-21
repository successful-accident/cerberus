package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/download"
	"github.com/successful-accident/cerberus/internal/engine"
	"github.com/successful-accident/cerberus/internal/resolve"
	"github.com/successful-accident/cerberus/internal/verify"
)

func (a *app) catalogCmd() *cobra.Command {
	var category string
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Browse the catalog",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return a.listCatalog(cmd, category) },
	}
	cmd.Flags().StringVar(&category, "category", "", "show only this category, by ID")

	var arch string
	check := &cobra.Command{
		Use:   "check [id...]",
		Short: "Resolve entries against the live feeds; exit 1 if any fails",
		RunE:  func(cmd *cobra.Command, ids []string) error { return a.checkCatalog(cmd, ids, arch) },
	}
	check.Flags().StringVar(&arch, "arch", "", "check only this architecture")
	cmd.AddCommand(check)
	return cmd
}

func signed(e *catalog.Entry) bool {
	return e.Signature != nil || slices.ContainsFunc(e.Steps, func(s catalog.Step) bool { return s.Clearsigned })
}

// listCatalog works without a config; it marks selected entries when there is one.
func (a *app) listCatalog(cmd *cobra.Command, category string) error {
	cat, err := a.loadCatalog()
	if err != nil {
		return err
	}
	cfg, err := config.Load(a.configPath)
	if err != nil && !errors.Is(err, config.ErrNoConfig) {
		return err
	}
	if category != "" && !slices.ContainsFunc(catalog.Categories, func(c catalog.Category) bool { return c.ID == category }) {
		var ids []string
		for _, c := range catalog.Categories {
			ids = append(ids, c.ID)
		}
		return fmt.Errorf("unknown category %q; use one of %s", category, strings.Join(ids, ", "))
	}
	out := cmd.OutOrStdout()
	for _, c := range catalog.Categories {
		if category != "" && c.ID != category {
			continue
		}
		entries := cat.InCategory(c.ID)
		if len(entries) == 0 {
			continue
		}
		var idw, namew int
		for _, e := range entries {
			idw, namew = max(idw, lipgloss.Width(e.ID)), max(namew, lipgloss.Width(e.Name))
		}
		fmt.Fprintln(out, c.Name)
		for _, e := range entries {
			mark := " "
			if cfg != nil && cfg.Selection(e.ID) != nil {
				mark = "*"
			}
			line := fmt.Sprintf("  %s %-*s  %-*s  %s", mark, idw, e.ID, namew, e.Name, strings.Join(slices.Sorted(maps.Keys(e.Arch)), ","))
			if signed(e) {
				line += "  signed"
			}
			fmt.Fprintln(out, line)
		}
		fmt.Fprintln(out)
	}
	return nil
}

type catalogJob struct {
	entry *catalog.Entry
	arch  string
}

// checkCatalog resolves every (entry, arch) pair, eight at a time, and checks
// that each release URL answers with a plausible size.
func (a *app) checkCatalog(cmd *cobra.Command, ids []string, arch string) error {
	cat, err := a.loadCatalog()
	if err != nil {
		return err
	}
	entries := cat.Entries
	if len(ids) > 0 {
		entries = nil
		for _, id := range ids {
			e, ok := cat.Get(id)
			if !ok {
				return fmt.Errorf("%q isn't in the catalog", id)
			}
			entries = append(entries, e)
		}
	}
	var jobs []catalogJob
	for _, e := range entries {
		for _, ar := range slices.Sorted(maps.Keys(e.Arch)) {
			if arch == "" || arch == ar {
				jobs = append(jobs, catalogJob{e, ar})
			}
		}
	}
	if len(jobs) == 0 {
		return errors.New("nothing to check")
	}

	type result struct {
		line string
		err  error
	}
	client := newClient()
	results := make([]chan result, len(jobs))
	sem := make(chan struct{}, 8)
	for i, j := range jobs {
		results[i] = make(chan result, 1)
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			line, err := checkEntry(cmd.Context(), cat, client, j)
			results[i] <- result{line, err}
		}()
	}
	failed := 0
	out := cmd.OutOrStdout()
	for i, j := range jobs {
		r := <-results[i]
		if r.err != nil {
			failed++
			fmt.Fprintf(out, "✗ %s %s: %v\n", j.entry.ID, j.arch, r.err)
			continue
		}
		fmt.Fprintln(out, r.line)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(jobs))
	}
	return nil
}

// checkEntry returns the ✓ line for one entry and architecture.
func checkEntry(ctx context.Context, cat *catalog.Catalog, client *download.Client, j catalogJob) (string, error) {
	e := j.entry
	opt := resolve.Options{Arch: j.arch}
	var kr *verify.Keyring
	if len(e.Keys) > 0 {
		keys, err := cat.KeysFor(e)
		if err != nil {
			return "", err
		}
		if kr, err = verify.NewKeyring(keys, e.Fingerprints); err != nil {
			return "", err
		}
		opt.Verifier = kr
	}
	rel, err := resolve.Resolve(ctx, client, e, opt)
	if err != nil {
		return "", err
	}
	size, err := client.Size(ctx, rel.URL)
	switch {
	case err != nil:
		return "", fmt.Errorf("size of %s: %w", rel.URL, err)
	case size >= 0 && size < 1_000_000:
		return "", fmt.Errorf("%s is implausibly small (%d bytes)", rel.URL, size)
	}
	sizeText := "size unknown"
	if size >= 0 {
		sizeText = engine.HumanSize(size)
	}
	trust := "unsigned"
	switch {
	case rel.SignedBy != "":
		trust = "signed by " + rel.SignedBy[:min(16, len(rel.SignedBy))]
	case rel.ISOSignatureURL != "":
		// The signature covers the ISO, which a check doesn't download, so
		// confirm the signature file exists and names a pinned key.
		if kr == nil {
			return "", fmt.Errorf("%s declares an ISO signature but pins no keys", e.ID)
		}
		doc, err := client.Get(ctx, rel.ISOSignatureURL)
		if err != nil {
			return "", fmt.Errorf("ISO signature: %w", err)
		}
		fp, err := kr.CheckIssuer(doc.Body)
		if err != nil {
			return "", fmt.Errorf("ISO signature %s: %w", rel.ISOSignatureURL, err)
		}
		trust = "ISO signed by " + fp[:16] + " (verified at download)"
	}
	return fmt.Sprintf("✓ %s %s %s %s %s %s %s", e.ID, j.arch, rel.Version, rel.Filename, sizeText, rel.Checksum.Algo, trust), nil
}
