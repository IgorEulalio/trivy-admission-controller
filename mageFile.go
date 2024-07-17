//go:build mage
// +build mage

package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const (
	dockerRepo string = "igoreulalio"
	imageName  string = "trivy-admission-controller"
)

func (Build) Local() error {
	fmt.Println("Building the Go application locally...")

	env := map[string]string{
		"CGO_ENABLED": "0",
		"GOOS":        "linux",
		"GOARCH":      "amd64",
	}

	if err := sh.RunWithV(env, "go", "build", "-ldflags=-s -w -extldflags='-static'", "-a", "-installsuffix", "cgo", "-o", "trivy-admission-controller", "main.go"); err != nil {
		return fmt.Errorf("failed to build the application: %w", err)
	}

	fmt.Println("Build completed successfully.")
	return nil
}

// Push pushes the images to DockerHub
func (Push) Images() error {
	mg.Deps(Build.Local)

	fmt.Println("Building image...")
	randomTag := generateRandomString(6)
	devTag := fmt.Sprintf("dev-%s", randomTag)

	imageWithRepo := fmt.Sprintf("%s/%s:%s", dockerRepo, imageName, devTag)
	os.Setenv("CGO_ENABLED", "0")
	os.Setenv("GOOS", "linux")
	os.Setenv("GOARCH", "amd64")

	if err := sh.RunV("docker", "buildx", "create", "--use"); err != nil {
		return err
	}

	if err := sh.RunV("docker", "buildx", "build", "--platform", "linux/amd64", "-t", imageWithRepo, "--push", "."); err != nil {
		return err
	}

	fmt.Println("Image built: ", imageWithRepo)

	return nil
}

// generateRandomString generates a random string of the specified length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var seededRand = rand.Reader

	b := make([]byte, length)
	for i := range b {
		num, _ := rand.Int(seededRand, big.NewInt(int64(len(charset))))
		b[i] = charset[num.Int64()]
	}
	return string(b)
}

// getVersion returns the current version of the application (stub implementation)
func getVersion() string {
	return "v1.0.0" // replace with your actual version retrieval logic
}

// getCommit returns the current commit hash (stub implementation)
func getCommit() string {
	return "DEV-" // replace with your actual commit retrieval logic
}

// Build is a namespace for build-related tasks.
type Push mg.Namespace

type Build mg.Namespace
