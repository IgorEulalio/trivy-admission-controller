package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/cache"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Handler struct {
	Cache cache.Cache
}

func NewHandler(c cache.Cache) *Handler {
	return &Handler{Cache: c}
}

const (
	strAllowed = "allowed"
	strDenied  = "denied"
)

func (h Handler) Validate(w http.ResponseWriter, r *http.Request) {
	logger := logging.Logger()

	if r.Method != "POST" {
		http.Error(w, "Please send with POST http method", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var admissionReview admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &admissionReview); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	scanner, err := scan.NewFromAdmissionReview(admissionReview)
	if err != nil {
		return
	}

	var imagesToBeScanned []string
	var imagesDeniedOnCache []string
	var imagesAllowedOnCache []string
	var digest string
	var image *scan.Image
	var scanResults []scan.ScanResult
	shallRetrieveImageFromCache := true

	for _, imagePullString := range scanner.ImagesPullStrings {
		image, err = scan.NewImageFromPullString(imagePullString)
		if err != nil {
			shallRetrieveImageFromCache = false
			logger.Warn().Msgf("error parsing image manifest into repository and tag, will not attemp to fetch image on cache: %v", err)
		} else {
			digest, err = image.GetDigest()
			image.Digest = digest // TODO - Improve this
			if err != nil {
				logger.Warn().Msgf("error getting image manifest, will not attemp to fetch image on cache: %v", err)
			}
		}
		if shallRetrieveImageFromCache {
			logger.Debug().Msgf("attempting to get image from cache %v with digest %v", image.PullString, image.Digest)
			allowOrDeny, ok := h.Cache.Get(digest)
			if !ok {
				imagesToBeScanned = append(imagesToBeScanned, image.PullString)
			} else if allowOrDeny == strAllowed {
				imagesAllowedOnCache = append(imagesAllowedOnCache, image.PullString)
				logger.Debug().Msgf("image %v with digest %v found on cache with status %v, skipping scan", image.PullString, image.Digest, strAllowed)
			} else if allowOrDeny == strDenied {
				imagesDeniedOnCache = append(imagesDeniedOnCache, image.PullString)
				logger.Debug().Msgf("image %v with digest %v found on cache with status %v, denying scan", image.PullString, image.Digest, strDenied)
			}
		} else {
			imagesToBeScanned = append(imagesToBeScanned, image.PullString)
		}
	}

	var containsVulnerability bool
	var admissionResponse *admissionv1.AdmissionResponse

	if len(imagesToBeScanned) == 0 && len(imagesDeniedOnCache) == 0 {
		admissionResponse = &admissionv1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status{
				Message: fmt.Sprintf("image scan result cached for images: %v, allowing.", strings.Join(imagesAllowedOnCache, ", ")),
			},
		}
	} else if len(imagesDeniedOnCache) > 0 {
		admissionResponse = &admissionv1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status{
				Message: fmt.Sprintf("image scan result cached for images: %v, denying.", strings.Join(imagesDeniedOnCache, ", ")),
			},
		}
	} else {
		scanResults, err = scanner.Scan(imagesToBeScanned)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	for _, result := range scanResults {
		containsVulnerability, err = result.HasVulnerabilities()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if containsVulnerability {
			admissionResponse = &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: fmt.Sprintf("Image %s with digest %s contains vulnerabilities", result.ArtifactName, result.Metadata.ImageID),
				},
			}

			// ImageID from trivy scan result matches config.digest from docker hub response
			err = h.Cache.Set(result.Metadata.ImageID, strDenied, 1*time.Hour)
			if err != nil {
				logger.Warn().Msgf("Error setting cache: %v", err)
			}
			logger.Debug().Msgf(admissionResponse.Result.Message)
		} else {
			admissionResponse = &admissionv1.AdmissionResponse{
				Allowed: true,
				Result: &metav1.Status{
					Message: fmt.Sprintf("Image %s with digest %s does not contain vulnerabilities", result.ArtifactName, result.Metadata.ImageID),
				},
			}
			// ImageID from trivy scan result matches config.digest from docker hub response
			err = h.Cache.Set(result.Metadata.ImageID, strAllowed, 1*time.Hour)
			if err != nil {
				logger.Warn().Msgf("Error setting cache: %v", err)
			}
			logger.Debug().Msgf(admissionResponse.Result.Message)
		}
	}

	admissionReview.Response = admissionResponse
	admissionReview.Response.UID = admissionReview.Request.UID

	response, err := json.Marshal(admissionReview)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}
