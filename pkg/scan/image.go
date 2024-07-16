package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/config"
)

type Image struct {
	Repository      string
	Tag             string
	PullString      string
	Digest          string
	FormmatedDigest string
	Allowed         bool
}

type ManifestConfig struct {
	MediaType string `json:"mediaType"`
	Size      int    `json:"size"`
	Digest    string `json:"digest"`
}

type ManifestResponse struct {
	Manifests     []Manifest     `json:"manifests"`
	MediaType     string         `json:"mediaType"`
	SchemaVersion int            `json:"schemaVersion"`
	Config        ManifestConfig `json:"config"`
}

type Manifest struct {
	Annotations Annotations `json:"annotations"`
	Digest      string      `json:"digest"`
	MediaType   string      `json:"mediaType"`
	Platform    Platform    `json:"platform"`
	Size        int         `json:"size"`
}

type Annotations struct {
	ComDockerOfficialImagesBashbrewArch string    `json:"com.docker.official-images.bashbrew.arch"`
	OrgOpencontainersImageBaseDigest    string    `json:"org.opencontainers.image.base.digest"`
	OrgOpencontainersImageBaseName      string    `json:"org.opencontainers.image.base.name"`
	OrgOpencontainersImageCreated       time.Time `json:"org.opencontainers.image.created"`
	OrgOpencontainersImageRevision      string    `json:"org.opencontainers.image.revision"`
	OrgOpencontainersImageSource        string    `json:"org.opencontainers.image.source"`
	OrgOpencontainersImageURL           string    `json:"org.opencontainers.image.url"`
	OrgOpencontainersImageVersion       string    `json:"org.opencontainers.image.version"`
}

// Platform represents the platform details for a manifest.
type Platform struct {
	Architecture string `json:"architecture"`
	Os           string `json:"os"`
}

type AuthResponse struct {
	Token string `json:"token"`
}

func NewImageFromPullString(pullString string) (*Image, error) {
	repository, tag, found := strings.Cut(pullString, ":")
	if !found {
		return nil, fmt.Errorf("can't parse pullstring, : identifier not found")
	}
	return &Image{
		Repository: repository,
		Tag:        tag,
		PullString: pullString,
	}, nil
}

func (i Image) GetDigest() (string, error) {
	var repo string

	contains := strings.Contains(i.Repository, "/")
	if contains {
		repo = i.Repository
	} else {
		repo = fmt.Sprintf("library/%s", i.Repository)
	}

	manifest, err := i.GetImageManifest(repo, i.Tag, config.Cfg.DockerToken)
	if err != nil {
		return "", fmt.Errorf("error getting manifest: %w", err)
	}

	if len(manifest.Manifests) > 1 {
		return "", fmt.Errorf("multiple manifests found, cache for multi-archs not supported ")
	}

	if manifest.Config.Digest == "" {
		return "", fmt.Errorf("no digest found in manifest response config")
	}

	return manifest.Config.Digest, nil
}

func (i Image) GetImageManifest(repository, tag, encodedToken string) (*ManifestResponse, error) {
	manifestURL := fmt.Sprintf("https://registry-1.docker.io/v2/%s/manifests/%s", repository, tag)
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		return nil, err
	}

	username, password, _ := strings.Cut(encodedToken, ":")
	dockerHubToken, err := getDockerHubToken(username, password, repository)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", dockerHubToken))
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get manifest: %s, %s", resp.Status, string(body))
	}

	var manifest ManifestResponse
	if err = json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

func getDockerHubToken(username string, password string, repository string) (string, error) {
	url := "https://auth.docker.io/token"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	query := req.URL.Query()
	query.Add("service", "registry.docker.io")
	query.Add("scope", fmt.Sprintf("repository:%v:pull", repository))
	req.URL.RawQuery = query.Encode()

	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get token: %s, %s", resp.Status, string(body))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", err
	}

	return authResp.Token, nil
}
