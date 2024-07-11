package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan"
	admissionv1 "k8s.io/api/admission/v1"
)

func Validate(w http.ResponseWriter, r *http.Request) {

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

	// Implement your validation logic here
	allowed := true

	scanner, err := scan.NewFromAdmissionReview(admissionReview)
	if err != nil {
		return
	}

	outputFilePath, err := scanner.Scan()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	allowed, err = scanner.AnalyzeScanResult(outputFilePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	admissionResponse := &admissionv1.AdmissionResponse{
		Allowed: allowed,
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
