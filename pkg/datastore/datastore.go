package datastore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/cache"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/config"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/image"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/kubernetes"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type DataStore interface {
	GetImagesThatNeedScan(images []image.Image) (imagesToBeScanned []image.Image, imagesDeniedOnCache []image.Image, imagesAllowedOnCache []image.Image)
	GetImageFromDataStore(image image.Image) (*image.Image, error)
	SetImageOnDataStore(image image.Image, duration time.Duration) error
}

type EtcdAndCacheDataStore struct {
	Cache            cache.Cache
	KubernetesClient kubernetes.Client
}

func NewEtcdAndCacheDataStore(k kubernetes.Client, c cache.Cache) EtcdAndCacheDataStore {
	return EtcdAndCacheDataStore{
		Cache:            c,
		KubernetesClient: k,
	}
}

func (s EtcdAndCacheDataStore) GetImagesThatNeedScan(images []image.Image) (imagesToBeScanned []image.Image, imagesDeniedOnCache []image.Image, imagesAllowedOnCache []image.Image) {
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

func (s EtcdAndCacheDataStore) GetImageFromDataStore(image image.Image) (*image.Image, error) {
	logger := logging.Logger()

	allowOrDeny, presentOnCache := s.Cache.Get(image.FormattedDigest)
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
	resource, err := s.KubernetesClient.GetResource(gvr, config.Cfg.Namespace, formmatedDigest)
	if err != nil {
		return &image, err
	}
	logger.Debug().Msgf("image %v with digest %v found on kubernetes store with status %v", image.PullString, image.Digest, resource.Object["spec"].(map[string]interface{})["allowed"].(bool))

	image.Allowed = resource.Object["spec"].(map[string]interface{})["allowed"].(bool)
	image.FormattedDigest = formmatedDigest
	return &image, nil
}

func (s EtcdAndCacheDataStore) SetImageOnDataStore(image image.Image, duration time.Duration) error {

	err := s.Cache.Set(image.FormattedDigest, image.Allowed, duration)
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
				"name": image.FormattedDigest,
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
