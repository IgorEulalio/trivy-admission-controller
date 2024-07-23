package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/cache"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/config"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/image"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/kubernetes"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan/result"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Scanner struct {
	OutputDir        string
	ScannerModes     []string
	Cache            cache.Cache
	KubernetesClient kubernetes.Client
}

const (
	StrAllowed     = "allowed"
	filePermission = 0755
)

func NewScanner(c cache.Cache, client kubernetes.Client) (*Scanner, error) {

	err := os.Mkdir(config.Cfg.OutputDir, filePermission)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("fail to create output directory for scans: %v", err)
	}

	return &Scanner{
		OutputDir:        config.Cfg.OutputDir,
		ScannerModes:     []string{"vuln"},
		Cache:            c,
		KubernetesClient: client,
	}, nil
}

func (s Scanner) Scan(imagesToBeScanned []image.Image) ([]result.ScanResult, error) {
	logger := logging.Logger()

	var results []result.ScanResult

	for _, imageToBeScanned := range imagesToBeScanned {
		outputFilePath := fmt.Sprintf("%s/%s-%s.json", s.OutputDir, "scan", time.Now().Format("02:15:04"))
		command := fmt.Sprintf("%s image %s -o %s --scanners %s --format json", config.Cfg.TrivyPath, imageToBeScanned.PullString, outputFilePath, strings.Join(s.ScannerModes, ","))
		logger.Debug().Msgf("Running command: %s for image %s", command, imageToBeScanned.PullString)

		cmd := exec.Command("sh", "-c", command)
		var out, stderr strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		err := cmd.Run()
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

func (s Scanner) GetImagesThatNeedScan(images []image.Image) (imagesToBeScanned []image.Image, imagesDeniedOnCache []image.Image, imagesAllowedOnCache []image.Image) {
	logger := logging.Logger()

	var toBeScanned []image.Image
	var deniedImages []image.Image
	var allowedImages []image.Image
	var err error
	shallAttemptToRetrieveImage := true

	for _, i := range images {
		if i.Digest == "" && err != nil {
			shallAttemptToRetrieveImage = false
			logger.Warn().Msgf("image digest is empty, will not attemp to retrieve image from data store: %v", err)
		}
		if shallAttemptToRetrieveImage {
			logger.Debug().Msgf("attempting to get image from data store %v with digest %v", i.PullString, i.Digest)
			imageFromDataStore, err := s.GetImageFromDataStore(i)
			if err != nil {
				toBeScanned = append(toBeScanned, i)
			} else if imageFromDataStore.Allowed {
				allowedImages = append(allowedImages, i)
			} else if !imageFromDataStore.Allowed {
				deniedImages = append(deniedImages, i)
			}
		} else {
			toBeScanned = append(toBeScanned, i)
		}
	}

	return toBeScanned, deniedImages, allowedImages
}

func (s Scanner) GetImageFromDataStore(image image.Image) (*image.Image, error) {
	logger := logging.Logger()

	allowOrDeny, presentOnCache := s.Cache.Get(image.FormmatedDigest)
	if presentOnCache {
		logger.Debug().Msgf("image %v with digest %v found on cache with allowed %v", image.PullString, image.Digest, allowOrDeny)
		if allowOrDeny == "true" {
			image.Allowed = true
			return &image, nil
		}
		image.Allowed = false
		return &image, nil
	}

	gvr := schema.GroupVersionResource{
		Group:    "trivyac.io",
		Version:  "v1",
		Resource: kubernetes.ResourcePlural,
	}

	formmatedDigest := strings.ReplaceAll(image.Digest, ":", "-")

	resource, err := s.KubernetesClient.Dynamic.Resource(gvr).Namespace(config.Cfg.Namespace).Get(context.TODO(), formmatedDigest, metav1.GetOptions{})
	if err != nil {
		return &image, err
	}
	logger.Debug().Msgf("image %v with digest %v found on kubernetes store with status %v", image.PullString, image.Digest, resource.Object["spec"].(map[string]interface{})["allowed"].(bool))

	image.Allowed = resource.Object["spec"].(map[string]interface{})["allowed"].(bool)
	image.FormmatedDigest = formmatedDigest
	return &image, nil
}

func (s Scanner) SetImageOnDataStore(image image.Image, duration time.Duration) error {

	err := s.Cache.Set(image.FormmatedDigest, image.Allowed, duration)
	if err != nil {
		return fmt.Errorf("failed to set resource on cache: %v", err)
	}

	gvr := schema.GroupVersionResource{
		Group:    "trivyac.io",
		Version:  "v1",
		Resource: kubernetes.ResourcePlural,
	}

	scannedImageResource := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "trivyac.io/v1",
			"kind":       "ScannedImage",
			"metadata": map[string]interface{}{
				"name": image.FormmatedDigest,
			},
			"spec": map[string]interface{}{
				"imageDigest":     image.Digest,
				"allowed":         image.Allowed,
				"imagePullString": image.PullString,
			},
		},
	}

	_, err = kubernetes.GetClient().Dynamic.Resource(gvr).Namespace(config.Cfg.Namespace).Create(context.TODO(), scannedImageResource, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create resource on kubernetes data store: %v", err)
	}

	return nil
}

func getResultFromFileSystem(path string) (*result.ScanResult, error) {
	var result result.ScanResult

	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if err = json.Unmarshal(file, &result); err != nil {
		return nil, fmt.Errorf("error unmarshaling file: %w", err)
	}

	return &result, nil
}
