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
	"github.com/IgorEulalio/trivy-admission-controller/pkg/kubernetes"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
	v1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Scanner struct {
	ImagesPullStrings []string
	DryRun            bool
	OutputDir         string
	ScannerModes      []string
	Cache             cache.Cache
	KubernetesClient  kubernetes.Client
}

const (
	StrAllowed     = "allowed"
	StrDenied      = "denied"
	filePermission = 0755
)

func NewFromAdmissionReview(ar v1.AdmissionReview, c cache.Cache, client kubernetes.Client) (Scanner, error) {

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
		KubernetesClient:  client,
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
		command := fmt.Sprintf("%s image %s -o %s --scanners %s --format json", config.Cfg.TrivyPath, image, outputFilePath, strings.Join(s.ScannerModes, ","))
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

// that method should return images in the future
// note below comments
func (s Scanner) GetImagesThatNeedScan() (imagesToBeScanned []string, imagesDeniedOnCache []string, imagesAllowedOnCache []string) {
	logger := logging.Logger()

	var toBeScanned []string
	var deniedImages []string
	var allowedImages []string
	var digest string
	var image *Image

	shallAttemptToRetrieveImage := true
	var err error

	for _, imagePullString := range s.ImagesPullStrings {
		// we need to refactor this to make sure we allways get images,
		// images should be the main struct in the long term that will support all actions
		image, err = NewImageFromPullString(imagePullString)
		if err != nil {
			shallAttemptToRetrieveImage = false
			logger.Warn().Msgf("error parsing image manifest into repository and tag, will not attemp to fetch image on cache: %v", err)
		} else {
			// image.GetDigest should depend on type, and we'll need to be able to better create images
			digest, err = image.GetDigest()
			image.Digest = digest // TODO - Improve this
			if err != nil {
				logger.Warn().Msgf("error getting image manifest, will not attemp to fetch image on cache: %v", err)
				shallAttemptToRetrieveImage = false
			}
		}
		if shallAttemptToRetrieveImage {
			logger.Debug().Msgf("attempting to get image from data store %v with digest %v", image.PullString, image.Digest)
			imageFromDataStore, err := s.GetImageFromDataStore(*image)
			if err != nil {
				toBeScanned = append(imagesToBeScanned, imagePullString)
			} else if imageFromDataStore.Allowed {
				allowedImages = append(imagesAllowedOnCache, imagePullString)
			} else if !imageFromDataStore.Allowed {
				deniedImages = append(imagesDeniedOnCache, imagePullString)
			}
		} else {
			toBeScanned = append(imagesToBeScanned, imagePullString)
		}
	}

	return toBeScanned, deniedImages, allowedImages
}

// TODO - need to verify pointer stuff here
func (s Scanner) GetImageFromDataStore(image Image) (*Image, error) {
	logger := logging.Logger()

	allowOrDeny, ok := s.Cache.Get(image.Digest)
	if ok {
		logger.Debug().Msgf("image %v with digest %v found on cache with allowed %v", image.PullString, image.Digest, allowOrDeny)
		if allowOrDeny == StrAllowed {
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

func (s Scanner) SetImageOnDataStore(id string, status string, duration time.Duration) error {
	var allowed bool
	formattedDigest := strings.ReplaceAll(id, ":", "-")

	if status == StrAllowed {
		allowed = true
	}

	err := s.Cache.Set(id, allowed, duration)
	if err != nil {
		return fmt.Errorf("failed to set resource on cache: %v", err)
	}

	gvr := schema.GroupVersionResource{
		Group:    "trivyac.io",
		Version:  "v1",
		Resource: kubernetes.ResourcePlural,
	}

	image := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "trivyac.io/v1",
			"kind":       "ScannedImage",
			"metadata": map[string]interface{}{
				"name": formattedDigest,
			},
			"spec": map[string]interface{}{
				"imageDigest": id,
				"allowed":     allowed,
			},
		},
	}

	_, err = kubernetes.GetClient().Dynamic.Resource(gvr).Namespace(config.Cfg.Namespace).Create(context.TODO(), image, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create resource on kubernetes data store: %v", err)
	}

	return nil
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
