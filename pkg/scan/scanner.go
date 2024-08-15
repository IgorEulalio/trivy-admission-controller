package scan

import (
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/image"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan/result"
)

type Scanner interface {
	Scan(imagesToBeScanned []image.Image) ([]result.ScanResult, error)
	SetImageOnDataStore(image image.Image, duration time.Duration) error
}