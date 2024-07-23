package image

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/loader"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan/result"
	v1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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

func NewImageFromScanResult(scanResult result.ScanResult) (*Image, error) {
	image, err := newImageFromPullString(scanResult.ArtifactName, []string{})
	if err != nil {
		return nil, fmt.Errorf("error creating image from scan result: %v", err)
	}

	return image, nil
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
func getDigest(registry string, repo string, tag string, pullSecrets []string) (string, error) {

	image := Image{
		Repository:      repo,
		Tag:             tag,
		PullString:      fmt.Sprintf("%s/%s:%s", registry, repo, tag),
		Digest:          "",
		FormmatedDigest: "",
		Registry:        registry,
		Allowed:         false,
		PullSecrets:     pullSecrets,
	}

	loader := loader.NewLoader(image.PullString, image.PullSecrets)
	digest, err := loader.GetImageDigest()
	if err != nil {
		return "", err
	}

	return digest, nil
}

func extractContainerImagesAndPullSecretsFromPodSpec(podSpec *corev1.PodSpec) []Image {
	logger := logging.Logger()

	var images []Image
	for _, container := range podSpec.Containers {
		var pullSecrets []string
		if podSpec.ImagePullSecrets != nil {
			pullSecrets = make([]string, 0, len(podSpec.ImagePullSecrets))
			for _, pullSecret := range podSpec.ImagePullSecrets {
				pullSecrets = append(pullSecrets, pullSecret.Name)
			}
		}
		image, err := newImageFromPullString(container.Image, pullSecrets)
		if err != nil {
			logger.Warn().Msgf("Error obtaining image digest: %v", err)
		}
		image.PullSecrets = pullSecrets
		images = append(images, *image)
	}
	return images
}
