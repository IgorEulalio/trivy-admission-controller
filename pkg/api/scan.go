package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/config"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/datastore"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/image"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/loader"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan/result"
)

func NewScanHandler(loader loader.Loader, datastore datastore.DataStore) (*ScanHandler, error) {
	return &ScanHandler{loader: loader, Datastore: datastore}, nil
}

type ScanHandler struct {
	loader    loader.Loader
	Datastore datastore.DataStore
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

	err = h.Datastore.SetImageOnDataStore(*imageFromScan, time.Duration(config.Cfg.CacheConfig.ObjectTTL))
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
