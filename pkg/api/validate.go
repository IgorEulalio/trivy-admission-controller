package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/config"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/datastore"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/image"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/loader"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan/result"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ValidateHandler struct {
	Scanner   scan.Scanner
	Loader    loader.Loader
	DataStore datastore.DataStore
}

func NewValidateHandler(scanner scan.Scanner, loader loader.Loader, datastore datastore.DataStore) (*ValidateHandler, error) {
	return &ValidateHandler{Scanner: scanner, Loader: loader, DataStore: datastore}, nil
}

func (h ValidateHandler) Validate(w http.ResponseWriter, r *http.Request) {
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

	logger.Debug().Msgf("Received request: %s", body)

	var admissionReview admissionv1.AdmissionReview
	if err = json.Unmarshal(body, &admissionReview); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	images, err := image.NewImagesFromAdmissionReview(admissionReview, h.Loader)
	if err != nil {
		return
	}

	imagesToBeScanned, imagesDeniedOnCache, imagesAllowedOnCache := h.DataStore.GetImagesThatNeedScan(images)
	var containsVulnerability bool
	var admissionResponse *admissionv1.AdmissionResponse
	var scanResults []result.ScanResult

	if len(imagesToBeScanned) == 0 && len(imagesDeniedOnCache) == 0 {
		imagePullStrings := make([]string, len(imagesAllowedOnCache))
		for i, img := range imagesAllowedOnCache {
			imagePullStrings[i] = img.PullString
		}
		admissionResponse = &admissionv1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status{
				Message: fmt.Sprintf("image scan result present on data store for images: %v, allowing.", strings.Join(imagePullStrings, ", ")),
			},
		}
	} else if len(imagesDeniedOnCache) > 0 {
		imagePullStrings := make([]string, len(imagesDeniedOnCache))
		for i, img := range imagesDeniedOnCache {
			imagePullStrings[i] = img.PullString
		}
		admissionResponse = &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: fmt.Sprintf("image scan result present on data store for images: %v, denying.", strings.Join(imagePullStrings, ", ")),
			},
		}
	} else {
		scanResults, err = h.Scanner.Scan(imagesToBeScanned)
		if err != nil {
			logger.Error().Msgf("Error scanning images: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	for _, result := range scanResults {
		containsVulnerability, err = result.HasVulnerabilities()
		if err != nil {
			logger.Error().Msgf("Error verifying result: %v", err)
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
			imageFromScanResult, err := image.NewImageFromScanResult(result, h.Loader)
			if err != nil {
				logger.Warn().Msgf("Error creating image from scan result: %v", err)
			} else { // We should not fail if not able to input image into data store
				if imageFromScanResult.Digest != "" {
					err := h.DataStore.SetImageOnDataStore(*imageFromScanResult, time.Duration(config.Cfg.CacheConfig.ObjectTTL))
					if err != nil {
						logger.Warn().Msgf("Error inputing image into data store: %v", err)
					}
				}
			}
		} else {
			admissionResponse = &admissionv1.AdmissionResponse{
				Allowed: true,
				Result: &metav1.Status{
					Message: fmt.Sprintf("Image %s with digest %s does not contain vulnerabilities", result.ArtifactName, result.Metadata.ImageID),
				},
			}
			imageFromScanResult, err := image.NewImageFromScanResult(result, h.Loader)
			imageFromScanResult.Allowed = true
			if err != nil {
				logger.Warn().Msgf("Error creating image from scan result: %v", err)
			} else {
				if imageFromScanResult.Digest != "" {
					err := h.DataStore.SetImageOnDataStore(*imageFromScanResult, time.Duration(config.Cfg.CacheConfig.ObjectTTL))
					if err != nil {
						logger.Warn().Msgf("Error inputing image into data store: %v", err)
					}
				}
			}
		}
		logger.Debug().Bool("containsVulnerability", containsVulnerability).Msgf("Image %s with digest %s", result.ArtifactName, result.Metadata.ImageID)
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
