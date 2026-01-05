// Copyright 2021-2026 Zenauth Ltd.

package main

import (
	"cmp"
	"embed"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/alecthomas/kong"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/utils/merkletrie"
)

//go:embed templates
var templatesFS embed.FS

const changelogDirName = ".changelog"

type args struct {
	Add      addCmd      `cmd:""`
	Generate generateCmd `cmd:""`
}

type addCmd struct {
	Type        string `help:"Type of the entry" enum:"breaking,chore,deprecation,docs,enhancement,feature,fix" required:""`
	Description string `help:"Change description" required:""`
}

type generateCmd struct {
	From       string `help:"Reference to start of change log" required:""`
	NewVersion string `help:"New release version" required:""`
}

func main() {
	var args args
	ctx := kong.Parse(&args,
		kong.Name("changelog"),
		kong.Description("Manage changelog"),
		kong.UsageOnError(),
	)

	ctx.FatalIfErrorf(ctx.Run())
}

func (ac *addCmd) Run(k *kong.Kong) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	changelogDir := filepath.Join(workingDir, changelogDirName)
	if err := os.MkdirAll(changelogDir, 0o744); err != nil {
		return fmt.Errorf("failed to create changelog dir at %q: %w", changelogDir, err)
	}

	entryTemplate, err := template.ParseFS(templatesFS, "templates/entry.tmpl")
	if err != nil {
		return fmt.Errorf("failed to parse templates: %w", err)
	}

	entryFileName := filepath.Join(changelogDir, time.Now().UTC().Format("20060102_1504")+".txt")
	entryFile, err := os.Create(entryFileName)
	if err != nil {
		return fmt.Errorf("failed to create entry file %q: %w", entryFileName, err)
	}
	defer entryFile.Close()

	if err := entryTemplate.Execute(entryFile, struct {
		Type        string
		Description string
	}{
		Type:        ac.Type,
		Description: ac.Description,
	}); err != nil {
		return fmt.Errorf("failed to render entry: %w", err)
	}

	fmt.Fprintf(k.Stdout, "Changelog entry written to %s\n", entryFileName)
	return nil
}

type ChangelogSection struct {
	Title   string
	Type    string
	Entries []entry
}

type Changelog struct {
	Version  string
	Sections []ChangelogSection
}

func (gc *generateCmd) Run(k *kong.Kong) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	fromRevision := plumbing.Revision(gc.From)
	entries, err := getChangelogEntries(workingDir, fromRevision)
	if err != nil {
		return err
	}

	changelogData := Changelog{Version: gc.NewVersion}
	for _, section := range []struct {
		Type  string
		Title string
	}{
		{
			Type:  "breaking",
			Title: "Breaking changes",
		},
		{
			Type:  "deprecation",
			Title: "Deprecations",
		},
		{
			Type:  "feature",
			Title: "Features",
		},
		{
			Type:  "enhancement",
			Title: "Enhancements",
		},
		{
			Type:  "fix",
			Title: "Bug fixes",
		},
		{
			Type:  "docs",
			Title: "Documentation",
		},
		{
			Type:  "chore",
			Title: "Other",
		},
	} {
		if entryList, exists := entries[section.Type]; exists {
			slices.SortFunc(entryList, func(a, b entry) int {
				return cmp.Compare(a.Name, b.Name)
			})

			changelogData.Sections = append(changelogData.Sections, ChangelogSection{
				Title:   section.Title,
				Type:    section.Type,
				Entries: entryList,
			})
		}
	}

	changelogTemplate, err := template.ParseFS(templatesFS, "templates/changelog.tmpl")
	if err != nil {
		return fmt.Errorf("failed to parse changelog template: %w", err)
	}

	if err := changelogTemplate.Execute(k.Stdout, changelogData); err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	return nil
}

type entry struct {
	Name        string
	Type        string
	Description string
}

func getChangelogEntries(workingDir string, fromRevision plumbing.Revision) (map[string][]entry, error) {
	repo, err := git.PlainOpen(workingDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open git repo: %w", err)
	}

	fromTree, err := getTree(repo, fromRevision)
	if err != nil {
		return nil, fmt.Errorf("failed to get from tree: %w", err)
	}

	toTree, err := getTree(repo, plumbing.Revision(plumbing.HEAD))
	if err != nil {
		return nil, fmt.Errorf("failed to get to tree: %w", err)
	}

	changes, err := fromTree.Diff(toTree)
	if err != nil {
		return nil, fmt.Errorf("failed to diff: %w", err)
	}

	changelogFiles := make(map[string]struct{})
	for _, change := range changes {
		action, err := change.Action()
		if err != nil {
			return nil, fmt.Errorf("failed to get action for change: %w", err)
		}

		switch action {
		case merkletrie.Insert, merkletrie.Modify:
			if filepath.Base(filepath.Dir(change.To.Name)) == changelogDirName {
				changelogFiles[change.To.Name] = struct{}{}
			}
		}
	}

	entries := make(map[string][]entry)
	for file := range changelogFiles {
		entry, err := createEntry(file)
		if err != nil {
			log.Printf("Failed to create entry from %s: %v", file, err)
			continue
		}

		entries[entry.Type] = append(entries[entry.Type], entry)
	}

	return entries, nil
}

func getTree(repo *git.Repository, revision plumbing.Revision) (*object.Tree, error) {
	commitHash, err := repo.ResolveRevision(revision)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve revision %s: %w", revision, err)
	}

	commit, err := repo.CommitObject(*commitHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit: %w", err)
	}

	return commit.Tree()
}

func createEntry(fileName string) (entry, error) {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return entry{}, fmt.Errorf("failed to read file: %w", err)
	}

	lines := slices.Collect(strings.Lines(string(contents)))
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "type:") {
		return entry{}, errors.New("invalid changelog entry")
	}

	entryType := strings.TrimSpace(strings.TrimPrefix(lines[0], "type:"))
	var description string
	if len(lines) > 2 {
		// Use Asciidoc continuation for complex Descriptions.
		description = fmt.Sprintf("%s+\n%s\n", lines[1], strings.Join(lines[2:], ""))
	} else {
		description = lines[1]
	}

	return entry{
		Name:        strings.TrimSuffix(filepath.Base(fileName), ".txt"),
		Type:        entryType,
		Description: description,
	}, nil
}
