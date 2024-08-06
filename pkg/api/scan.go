package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/cache"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/config"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/image"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/kubernetes"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan/result"
)

func NewScanHandler(c cache.Cache, client *kubernetes.Client, loader image.Loader) (*ScanHandler, error) {
	scanner, err := scan.NewScanner(c, *client)
	if err != nil {
		return nil, err
	}
	return &ScanHandler{Cache: c, KubernetesClient: *client, Scanner: *scanner, loader: loader}, nil
}

type ScanHandler struct {
	Cache            cache.Cache
	KubernetesClient kubernetes.Client
	Scanner          scan.Scanner
	loader           image.Loader
}

func (h ScanHandler) Scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Please send with POST http method", http.StatusMethodNotAllowed)
		return
	}

	var scanResult result.ScanResult
	err := json.NewDecoder(r.Body).Decode(&scanResult)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	containsVulnerability, err := scanResult.HasVulnerabilities()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	imageFromScan, err := image.NewImageFromScanResult(scanResult, h.loader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// leverage Allowed default value false
	if !containsVulnerability {
		imageFromScan.Allowed = true
	}

	err = h.Scanner.SetImageOnDataStore(*imageFromScan, time.Duration(config.Cfg.CacheConfig.ObjectTTL))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	imageBytes, err := json.Marshal(imageFromScan)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(imageBytes)
}
