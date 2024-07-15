//go:build mage
// +build mage

package main

import (
	"fmt"
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const (
	repoURL     string = "github.com/igoreulalio/trivy-admission-controller"
	projectName string = "trivy-admission-controller"
	dockerRepo  string = "igoreulalio/trivy-admission-controller"
)

type Lint mg.Namespace
type Build mg.Namespace
type Push mg.Namespace
type Release mg.Namespace

// lint:run runs linting
func (Lint) Run() error {
	if err := sh.RunV("golangci-lint", "--version"); err != nil {
		return err
	}
	if err := sh.RunV("golangci-lint", "run", "--timeout", "3m"); err != nil {
		return err
	}
	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}
	return nil
}

// lint:fix fixes linting
func (Lint) Fix() error {
	if err := sh.RunV("golangci-lint", "run", "--fix"); err != nil {
		return err
	}
	return nil
}

// test runs test
func Test() error {
	return sh.RunV("go", "test", "./...", "-race")
}

// run runs the app (with 'auto' as first argument, air is used to auto reload the app at each change)
//func Run(autoreload string) error {
//	if autoreload == "auto" {
//		return sh.RunV("air", "server", "-c", "config.yaml", "-r", "rules.yaml")
//	}
//	return sh.RunV("go", "run", "./...", "server", "-c", "config.yaml", "-r", "rules.yaml")
//}

// build:local builds a binary
func (Build) Local() error {
	ldFlags := generateLDFlags()

	fmt.Println(ldFlags)
	return sh.RunV("go", "build", "-trimpath", "-ldflags", ldFlags, "-o", projectName, ".")
}

// build:images builds images and not push
func (Build) Images() error {
	//exportLDFlags()
	os.Setenv("KO_DOCKER_REPO", dockerRepo)
	return sh.RunV("ko", "build", "--bare", "--sbom=none", "--tags", getVersion(), "--tags", getCommit(), "--tags", "latest",
		repoURL)
}

// push:images pushes the images to dockerhub
func (Push) Images() error {
	mg.Deps(Build.Images)
	os.Setenv("KO_DOCKER_REPO", dockerRepo)

	return sh.RunV("ko", "build", "--bare", "--sbom=none", "--tags", getVersion(), "--tags", getCommit(), "--tags", "latest",
		repoURL)
}

// release:snapshot creates a release with current commit
func (Release) Snapshot() error {
	exportLDFlags()
	return sh.RunV("goreleaser", "release", "--clean", "--snapshot", "--skip-sbom", "--skip-publish")
}

// release:tag creates a release from latest tag
func (Release) Tag() error {
	mg.Deps(Test)

	exportLDFlags()
	return sh.RunV("goreleaser", "release", "--clean", "--skip-sign", "--skip-sbom")
}

// clean cleans temp folders
func Clean() {
	files := []string{projectName, "dist"}

	for _, file := range files {
		sh.Rm(file)
	}
}

// exportLDFlags export as env vars the flags for go build
func exportLDFlags() {
	os.Setenv("LDFLAGS", generateLDFlags())
	fmt.Printf("export LDFLAGS=%s\n", os.Getenv("LDFLAGS"))
}

// getVersion gets a description of the commit, e.g. v0.30.1 (latest) or v0.30.1-32-gfe72ff73 (canary)
func getVersion() string {
	version, _ := sh.Output("git", "describe", "--tags", "--match=v*")
	if version != "" {
		return version
	}

	gitBranch, _ := sh.Output("git", "branch", "--show-current")

	// repo without any tags in it
	return gitBranch
}

// getCommit gets the hash of the current commit
func getCommit() string {
	commit, _ := sh.Output("git", "rev-parse", "--short", "HEAD")
	return commit
}

// getGitState gets the state of the git repository
func getGitState() string {
	_, err := sh.Output("git", "diff", "--quiet")
	if err != nil {
		return "dirty"
	}

	return "clean"
}

// getBuildDateTime gets the build date and time
func getBuildDateTime() string {
	result, _ := sh.Output("git", "log", "-1", "--pretty=%ct")
	if result != "" {
		sourceDateEpoch := fmt.Sprintf("@%s", result)
		date, _ := sh.Output("date", "-u", "-d", sourceDateEpoch, "+%Y-%m-%dT%H:%M:%SZ")
		return date
	}

	date, _ := sh.Output("date", "+%Y-%m-%dT%H:%M:%SZ")
	return date
}

func generateLDFlags() string {
	pkg := repoURL + "/configuration"
	return fmt.Sprintf("-X %[1]s.GitVersion=%[2]s -X %[1]s.gitCommit=%[3]s -X %[1]s.gitTreeState=%[4]s -X %[1]s.buildDate=%[5]s", pkg, getVersion(), getCommit(), getGitState(), getBuildDateTime())
}
