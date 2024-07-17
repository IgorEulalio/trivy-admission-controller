package image

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/kubernetes"
	v1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1Kubernetes "k8s.io/api/core/v1"
)

type Image struct {
	Repository      string
	Tag             string
	PullString      string
	Digest          string
	FormmatedDigest string
	Registry        string
	Allowed         bool
	PullSecrets     []string
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

// DockerConfig represents the structure of the docker config JSON.
type DockerConfig struct {
	Auths map[string]DockerAuth `json:"auths"`
}

// DockerAuth represents the auth structure within the docker config.
type DockerAuth struct {
	Auth string `json:"auth"`
}

func NewImagesFromAdmissionReview(ar v1.AdmissionReview) ([]Image, error) {
	var images []Image

	rawObject := ar.Request.Object.Raw
	groupVersionKind := ar.Request.Kind

	switch groupVersionKind.Kind {
	case "Pod":
		var pod corev1.Pod
		if err := json.Unmarshal(rawObject, &pod); err != nil {
			return nil, err
		}
		images = append(images, extractContainerImagesAndPullSecretsFromPodSpec(&pod.Spec)...)
	case "Deployment":
		var deploy appsv1.Deployment
		if err := json.Unmarshal(rawObject, &deploy); err != nil {
			return nil, err
		}
		images = append(images, extractContainerImagesAndPullSecretsFromPodSpec(&deploy.Spec.Template.Spec)...)
	case "DaemonSet":
		var ds appsv1.DaemonSet
		if err := json.Unmarshal(rawObject, &ds); err != nil {
			return nil, err
		}
		images = append(images, extractContainerImagesAndPullSecretsFromPodSpec(&ds.Spec.Template.Spec)...)
	default:
		return nil, fmt.Errorf("unsupported resource kind: %s", groupVersionKind.Kind)
	}

	return images, nil
}

func newImageFromPullString(pullString string, pullSecrets []string) (*Image, error) {
	var registry, repository, tag string

	repositoryWithRegistry, tag, found := strings.Cut(pullString, ":")
	if !found {
		tag = "latest"
	}

	parts := strings.SplitN(repositoryWithRegistry, "/", 2)

	if len(parts) == 1 {
		// Only image name is provided.
		registry = "docker.io"
		repository = "library/" + parts[0]
	} else if len(parts) == 2 {
		// Check if the first part contains a "." or ":" which indicates it's a registry.
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
			registry = parts[0]
			repository = parts[1]
		} else {
			// Default registry
			registry = "docker.io"
			repository = repositoryWithRegistry
		}
	}
	var digest string
	var err error
	digest, err = getDigest(registry, repository, tag, pullSecrets)
	if err != nil {
		return &Image{
			Registry:   registry,
			Repository: repository,
			Tag:        tag,
			PullString: pullString,
			Digest:     digest,
		}, err
	}
	return &Image{
		Registry:        registry,
		Repository:      repository,
		Tag:             tag,
		PullString:      pullString,
		Digest:          digest,
		FormmatedDigest: strings.ReplaceAll(digest, ":", "-"),
	}, nil
}

// getDigest returns the digest for a given image
// for now we ignore the registry parameter since we only support docker
func getDigest(_ string, repo string, tag string, pullSecrets []string) (string, error) {

	manifest, err := getImageManifest("", repo, tag, pullSecrets)
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

func getImageManifest(registry string, repository string, tag string, pullSecrets []string) (*ManifestResponse, error) {

	var dockerHubToken string
	var lastErr error

	manifestURL := fmt.Sprintf("https://registry-1.docker.io/v2/%s/manifests/%s", repository, tag)
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		return nil, err
	}

	for _, pullSecret := range pullSecrets {
		secret, err := kubernetes.GetClient().GetSecret("default", pullSecret)
		if err != nil {
			lastErr = err
			continue
		}
		username, password, err := getUserNamePasswordFromSecret(secret)
		if err != nil {
			lastErr = err
			continue
		}
		dockerHubToken, err = getDockerHubToken(username, password, repository)
		if err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
			continue
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("error getting docker hub token: %w", lastErr)
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

// getUserNamePasswordFromSecret extracts the username and password from the Kubernetes secret.
func getUserNamePasswordFromSecret(secret *v1Kubernetes.Secret) (string, string, error) {
	data, ok := secret.Data[".dockerconfigjson"]
	if !ok {
		return "", "", fmt.Errorf("secret is not of type .dockerconfigjson")
	}

	var dockerConfig DockerConfig
	if err := json.Unmarshal(data, &dockerConfig); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal docker config: %w", err)
	}

	for _, auth := range dockerConfig.Auths {
		decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode auth field: %w", err)
		}

		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid auth field format")
		}

		return parts[0], parts[1], nil
	}

	return "", "", fmt.Errorf("no auth field found in docker config")
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

func extractContainerImagesAndPullSecretsFromPodSpec(podSpec *corev1.PodSpec) []Image {
	var images []Image
	for _, container := range podSpec.Containers {
		var pullSecrets []string
		if podSpec.ImagePullSecrets != nil {
			pullSecrets = make([]string, 0, len(podSpec.ImagePullSecrets))
			for _, pullSecret := range podSpec.ImagePullSecrets {
				pullSecrets = append(pullSecrets, pullSecret.Name)
			}
		}
		image, _ := newImageFromPullString(container.Image, pullSecrets)
		image.PullSecrets = pullSecrets
		images = append(images, *image)
	}
	return images
}
