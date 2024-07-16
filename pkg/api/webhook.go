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
	if err = json.Unmarshal(body, &admissionReview); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	scanner, err := scan.NewFromAdmissionReview(admissionReview, h.Cache)
	if err != nil {
		return
	}

	imagesToBeScanned, imagesDeniedOnCache, imagesAllowedOnCache := scanner.GetImagesThatNeedScan()

	var containsVulnerability bool
	var admissionResponse *admissionv1.AdmissionResponse
	var scanResults []scan.ScanResult

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
			err = h.Cache.Set(result.Metadata.ImageID, scan.StrDenied, 1*time.Hour) // how can images that are not in registries contain an ImageID??
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
			err = h.Cache.Set(result.Metadata.ImageID, scan.StrAllowed, 1*time.Hour)
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
