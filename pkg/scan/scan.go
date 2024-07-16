package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/cache"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/config"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
	v1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

type Scanner struct {
	ImagesPullStrings []string
	DryRun            bool
	OutputDir         string
	ScannerModes      []string
	Cache             cache.Cache
}

const (
	StrAllowed     = "allowed"
	StrDenied      = "denied"
	filePermission = 0755
)

func NewFromAdmissionReview(ar v1.AdmissionReview, c cache.Cache) (Scanner, error) {

	images, err := getImagesFromAdmissionReview(ar)
	if err != nil {
		return Scanner{}, fmt.Errorf("error extracing images")
	}

	return Scanner{
		ImagesPullStrings: images,
		DryRun:            *ar.Request.DryRun,
		OutputDir:         config.Cfg.OutputDir,
		ScannerModes:      []string{"vuln"},
		Cache:             c,
	}, nil
}

func (s Scanner) Scan(imagesToBeScanned []string) ([]ScanResult, error) {
	logger := logging.Logger()

	var results []ScanResult

	err := os.Mkdir(s.OutputDir, filePermission)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}

	for _, image := range imagesToBeScanned {
		outputFilePath := fmt.Sprintf("%s/%s-%s.json", s.OutputDir, "scan", time.Now().Format("02:15:04"))
		command := fmt.Sprintf("/opt/homebrew/bin/trivy image %s -o %s --scanners %s --format json", image, outputFilePath, strings.Join(s.ScannerModes, ","))
		logger.Debug().Msgf("Running command: %s for image %s", command, image)

		cmd := exec.Command("sh", "-c", command)
		var out, stderr strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		err = cmd.Run()
		if err != nil {
			return nil, fmt.Errorf("error executing trivy scan: %v. Stdout: %v, Stderr: %v", err, out.String(), stderr.String())
		}

		result, err2 := getResultFromFileSystem(outputFilePath)
		if err2 != nil {
			return nil, err2
		}

		results = append(results, *result)
	}

	return results, nil
}

func (s Scanner) GetImagesThatNeedScan() (imagesToBeScanned []string, imagesDeniedOnCache []string, imagesAllowedOnCache []string) {
	logger := logging.Logger()

	var toBeScanned []string
	var deniedOnCache []string
	var allowedOnCache []string
	var digest string
	var image *Image

	shallRetrieveImageFromCache := true
	var err error

	for _, imagePullString := range s.ImagesPullStrings {
		image, err = NewImageFromPullString(imagePullString)
		if err != nil {
			shallRetrieveImageFromCache = false
			logger.Warn().Msgf("error parsing image manifest into repository and tag, will not attemp to fetch image on cache: %v", err)
		} else {
			digest, err = image.GetDigest()
			image.Digest = digest // TODO - Improve this
			if err != nil {
				logger.Warn().Msgf("error getting image manifest, will not attemp to fetch image on cache: %v", err)
			}
			shallRetrieveImageFromCache = false
		}
		if shallRetrieveImageFromCache {
			logger.Debug().Msgf("attempting to get image from cache %v with digest %v", image.PullString, image.Digest)
			allowOrDeny, ok := s.Cache.Get(digest)
			if !ok {
				toBeScanned = append(imagesToBeScanned, image.PullString)
			} else if allowOrDeny == StrAllowed {
				allowedOnCache = append(imagesAllowedOnCache, image.PullString)
				logger.Debug().Msgf("image %v with digest %v found on cache with status %v, skipping scan", image.PullString, image.Digest, StrAllowed)
			} else if allowOrDeny == StrDenied {
				deniedOnCache = append(imagesDeniedOnCache, image.PullString)
				logger.Debug().Msgf("image %v with digest %v found on cache with status %v, denying scan", image.PullString, image.Digest, StrDenied)
			}
		} else {
			toBeScanned = append(imagesToBeScanned, image.PullString)
		}
	}

	return toBeScanned, deniedOnCache, allowedOnCache
}

func getResultFromFileSystem(path string) (*ScanResult, error) {
	var result ScanResult

	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if err = json.Unmarshal(file, &result); err != nil {
		return nil, fmt.Errorf("error unmarshaling file: %w", err)
	}

	return &result, nil
}

func getImagesFromAdmissionReview(ar v1.AdmissionReview) ([]string, error) {

	var images []string

	rawObject := ar.Request.Object.Raw
	groupVersionKind := ar.Request.Kind

	switch groupVersionKind.Kind {
	case "Pod":
		var pod corev1.Pod
		if err := json.Unmarshal(rawObject, &pod); err != nil {
			return nil, err
		}
		images = append(images, extractContainerImagesFromPodSpec(&pod.Spec)...)
	case "Deployment":
		var deploy appsv1.Deployment
		if err := json.Unmarshal(rawObject, &deploy); err != nil {
			return nil, err
		}
		images = append(images, extractContainerImagesFromPodSpec(&deploy.Spec.Template.Spec)...)
	case "DaemonSet":
		var ds appsv1.DaemonSet
		if err := json.Unmarshal(rawObject, &ds); err != nil {
			return nil, err
		}
		images = append(images, extractContainerImagesFromPodSpec(&ds.Spec.Template.Spec)...)
	default:
		return nil, fmt.Errorf("unsupported resource kind: %s", groupVersionKind.Kind)
	}

	return images, nil
}

func extractContainerImagesFromPodSpec(podSpec *corev1.PodSpec) []string {
	var images []string
	for _, container := range podSpec.Containers {
		images = append(images, container.Image)
	}
	return images
}
