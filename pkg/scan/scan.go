package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
	v1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

type Scanner struct {
	ImagesName   []string
	DryRun       bool
	OutputDir    string
	ScannerModes []string
}

const filePermission = 0755

func NewFromAdmissionReview(ar v1.AdmissionReview) (Scanner, error) {

	images, err := getImagesFromAdmissionReview(ar)
	if err != nil {
		return Scanner{}, fmt.Errorf("Error extracing images")
	}

	var outputPath string
	outputPath, ok := os.LookupEnv("OUTPUT_PATH")
	if !ok {
		outputPath = "/tmp"
	}

	return Scanner{
		ImagesName:   images,
		DryRun:       *ar.Request.DryRun,
		OutputDir:    outputPath,
		ScannerModes: []string{"vuln"},
	}, nil
}

func (s Scanner) Scan() (outputFile string, error error) {
	logger := logging.Logger()

	err := os.Mkdir(s.OutputDir, filePermission)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}

	outputFilePath := fmt.Sprintf("%s-%s", "scan", time.Now().Format("02:15:04"))
	command := fmt.Sprintf("/opt/homebrew/bin/trivy image %s -o %s --scanners %s --format json", strings.Join(s.ImagesName, ","), outputFilePath, strings.Join(s.ScannerModes, ","))

	logger.Debug().Msgf("Running command: %s", command)

	cmd := exec.Command("sh", "-c", command)
	var out, stderr strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("command execution failed: %w, stderr: %s", err, stderr.String())
	}

	return outputFilePath, nil
}

func (s Scanner) AnalyzeScanResult(outputFilePath string, optSeverity ...string) (bool, error) {

	file, err := os.ReadFile(outputFilePath)
	if err != nil {
		return false, err
	}

	var result Result
	if err = json.Unmarshal(file, &result); err != nil {
		return false, err
	}

	if len(optSeverity) > 0 {
		severity := optSeverity[0]
		return result.ContainsVulnBySeverity(severity), nil
	}

	return result.ContainsVuln(), nil
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
	// Add more cases as needed
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
