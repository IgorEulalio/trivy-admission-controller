package image

import (
	"errors"
	"testing"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockLoader struct {
	mock.Mock
}

func (m *MockLoader) GetImageDigest(string, []string) (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

// Define a reusable type for test cases
type imageTestCase struct {
	name          string
	scanResult    result.ScanResult
	mockDigest    string
	mockError     error
	expectedImage *Image
	expectError   bool
}

// Define the test cases as a reusable slice
var imageTestCases = []imageTestCase{
	{
		name: "Valid image with latest tag",
		scanResult: result.ScanResult{
			ArtifactName: "nginx:latest",
		},
		mockDigest: "sha256:dummydigest",
		expectedImage: &Image{
			Registry:        "docker.io",
			Repository:      "library/nginx",
			Tag:             "latest",
			PullString:      "nginx:latest",
			Digest:          "sha256:dummydigest",
			FormattedDigest: "sha256-dummydigest",
		},
		expectError: false,
	},
	{
		name: "Valid image with specific tag",
		scanResult: result.ScanResult{
			ArtifactName: "nginx:1.21",
		},
		mockDigest: "sha256:anotherdigest",
		expectedImage: &Image{
			Registry:        "docker.io",
			Repository:      "library/nginx",
			Tag:             "1.21",
			PullString:      "nginx:1.21",
			Digest:          "sha256:anotherdigest",
			FormattedDigest: "sha256-anotherdigest",
		},
		expectError: false,
	},
	{
		name: "Image with missing tag defaults to latest",
		scanResult: result.ScanResult{
			ArtifactName: "nginx",
		},
		mockDigest: "sha256:dummydigest",
		expectedImage: &Image{
			Registry:        "docker.io",
			Repository:      "library/nginx",
			Tag:             "latest",
			PullString:      "nginx",
			Digest:          "sha256:dummydigest",
			FormattedDigest: "sha256-dummydigest",
		},
		expectError: false,
	},
	{
		name: "Error retrieving digest",
		scanResult: result.ScanResult{
			ArtifactName: "nginx:latest",
		},
		mockDigest: "",
		mockError:  errors.New("failed to get digest"),
		expectedImage: &Image{
			Registry:   "docker.io",
			Repository: "library/nginx",
			Tag:        "latest",
			PullString: "nginx:latest",
		},
		expectError: true,
	},
	{
		name: "Image with non-default registry, default repo (library) and tag.",
		scanResult: result.ScanResult{
			ArtifactName: "my.local.registry/nginx:latest",
		},
		mockDigest: "sha256:dummydigest",
		expectedImage: &Image{
			Registry:        "my.local.registry",
			Repository:      "nginx",
			Tag:             "latest",
			PullString:      "mylocalregistry/nginx:latest",
			Digest:          "sha256:dummydigest",
			FormattedDigest: "sha256-dummydigest",
		},
		expectError: false,
	},
	{
		name: "Image with non-default registry, custom repo and tag.",
		scanResult: result.ScanResult{
			ArtifactName: "my.local.registry/myrepo/myimage:latest",
		},
		mockDigest: "sha256:dummydigest",
		expectedImage: &Image{
			Registry:        "my.local.registry",
			Repository:      "myrepo/myimage",
			Tag:             "latest",
			PullString:      "my.local.registry/myrepo/myimage:latest",
			Digest:          "sha256:dummydigest",
			FormattedDigest: "sha256-dummydigest",
		},
		expectError: false,
	},
	{
		name: "Image with non-default registry, custom repo and missing tag default to latest.",
		scanResult: result.ScanResult{
			ArtifactName: "my.local.registry/myrepo/myimage",
		},
		mockDigest: "sha256:dummydigest",
		expectedImage: &Image{
			Registry:        "my.local.registry",
			Repository:      "myrepo/myimage",
			Tag:             "latest",
			PullString:      "my.local.registry/myrepo/myimage:latest",
			Digest:          "sha256:dummydigest",
			FormattedDigest: "sha256-dummydigest",
		},
		expectError: false,
	},
}

func TestNewImageFromScanResult(t *testing.T) {
	for _, tt := range imageTestCases {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := new(MockLoader)
			mockLoader.On("GetImageDigest").Return(tt.mockDigest, tt.mockError)

			img, err := NewImageFromScanResult(tt.scanResult, mockLoader)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, img)
				assert.Equal(t, tt.expectedImage.Digest, img.Digest)
				assert.Equal(t, tt.expectedImage.FormattedDigest, img.FormattedDigest)
				assert.Equal(t, tt.expectedImage.Registry, img.Registry)
				assert.Equal(t, tt.expectedImage.Repository, img.Repository)
				assert.Equal(t, tt.expectedImage.Tag, img.Tag)
			}

			mockLoader.AssertExpectations(t)
		})
	}
}
