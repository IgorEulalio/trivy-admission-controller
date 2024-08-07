package image

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type MockLoader struct {
	mock.Mock
}

func (m *MockLoader) GetImageDigest(string, []string) (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

type imageTestCase struct {
	name          string
	scanResult    result.ScanResult
	mockDigest    string
	mockError     error
	expectedImage *Image
	expectError   bool
}

type podSpecTestCase struct {
	name             string
	podSpec          *corev1.PodSpec
	mockDigest       string
	mockError        error
	expectedImages   []Image
	expectedWarnings int // Number of expected warnings
	expectError      bool
}

type admissionReviewTestCase struct {
	name            string
	admissionReview v1.AdmissionReview
	mockDigest      string
	mockError       error
	expectedImages  []Image
	expectError     bool
}

var admissionReviewTestCases = []admissionReviewTestCase{
	{
		name: "Valid Pod resource",
		admissionReview: createAdmissionReview("Pod", corev1.Pod{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "nginx:latest",
					},
				},
				ImagePullSecrets: []corev1.LocalObjectReference{
					{Name: "my-secret"},
				},
			},
		}),
		mockDigest: "sha256:dummydigest",
		expectedImages: []Image{
			{
				Registry:        "docker.io",
				Repository:      "library/nginx",
				Tag:             "latest",
				PullString:      "nginx:latest",
				Digest:          "sha256:dummydigest",
				FormattedDigest: "sha256-dummydigest",
				PullSecrets:     []string{"my-secret"},
			},
		},
		expectError: false,
	},
	{
		name: "Valid Deployment resource",
		admissionReview: createAdmissionReview("Deployment", appsv1.Deployment{
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Image: "nginx:1.21",
							},
						},
					},
				},
			},
		}),
		mockDigest: "sha256:anotherdigest",
		expectedImages: []Image{
			{
				Registry:        "docker.io",
				Repository:      "library/nginx",
				Tag:             "1.21",
				PullString:      "nginx:1.21",
				Digest:          "sha256:anotherdigest",
				FormattedDigest: "sha256-anotherdigest",
				PullSecrets:     []string{},
			},
		},
		expectError: false,
	},
	{
		name: "Valid Daemonset resource",
		admissionReview: createAdmissionReview("DaemonSet", appsv1.DaemonSet{
			Spec: appsv1.DaemonSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Image: "nginx:1.21",
							},
						},
					},
				},
			},
		}),
		mockDigest: "sha256:anotherdigest",
		expectedImages: []Image{
			{
				Registry:        "docker.io",
				Repository:      "library/nginx",
				Tag:             "1.21",
				PullString:      "nginx:1.21",
				Digest:          "sha256:anotherdigest",
				FormattedDigest: "sha256-anotherdigest",
				PullSecrets:     []string{},
			},
		},
		expectError: false,
	},
	{
		name: "Valid Statefulset resource",
		admissionReview: createAdmissionReview("StatefulSet", appsv1.StatefulSet{
			Spec: appsv1.StatefulSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Image: "nginx:1.21",
							},
						},
					},
				},
			},
		}),
		mockDigest: "sha256:anotherdigest",
		expectedImages: []Image{
			{
				Registry:        "docker.io",
				Repository:      "library/nginx",
				Tag:             "1.21",
				PullString:      "nginx:1.21",
				Digest:          "sha256:anotherdigest",
				FormattedDigest: "sha256-anotherdigest",
				PullSecrets:     []string{},
			},
		},
		expectError: false,
	},
	{
		name: "Invalid resource",
		admissionReview: createAdmissionReview("InvalidResource", appsv1.Deployment{
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Image: "nginx:1.21",
							},
						},
					},
				},
			},
		}),
		mockDigest: "sha256:anotherdigest",
		mockError:  fmt.Errorf("unsupported resource kind: %s", "InvalidResource"),
		expectedImages: []Image{
			{
				Registry:        "docker.io",
				Repository:      "library/nginx",
				Tag:             "1.21",
				PullString:      "nginx:1.21",
				Digest:          "sha256:anotherdigest",
				FormattedDigest: "sha256-anotherdigest",
				PullSecrets:     []string{},
			},
		},
		expectError: true,
	},
}

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

var podSpecTestCases = []podSpecTestCase{
	{
		name: "Single container with pull secrets",
		podSpec: &corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Image: "nginx:latest",
				},
			},
			ImagePullSecrets: []corev1.LocalObjectReference{
				{Name: "my-secret"},
			},
		},
		mockDigest: "sha256:dummydigest",
		expectedImages: []Image{
			{
				Registry:        "docker.io",
				Repository:      "library/nginx",
				Tag:             "latest",
				PullString:      "nginx:latest",
				Digest:          "sha256:dummydigest",
				FormattedDigest: "sha256-dummydigest",
				PullSecrets:     []string{"my-secret"},
			},
		},
		expectedWarnings: 0,
		expectError:      false,
	},
	{
		name: "Multiple containers without pull secrets",
		podSpec: &corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Image: "nginx:latest",
				},
				{
					Image: "redis:alpine",
				},
			},
		},
		mockDigest: "sha256:genericdigest",
		expectedImages: []Image{
			{
				Registry:        "docker.io",
				Repository:      "library/nginx",
				Tag:             "latest",
				PullString:      "nginx:latest",
				Digest:          "sha256:genericdigest",
				FormattedDigest: "sha256-genericdigest",
				PullSecrets:     []string{},
			},
			{
				Registry:        "docker.io",
				Repository:      "library/redis",
				Tag:             "alpine",
				PullString:      "redis:alpine",
				Digest:          "sha256:genericdigest",
				FormattedDigest: "sha256-genericdigest",
				PullSecrets:     []string{},
			},
		},
		expectedWarnings: 0,
		expectError:      false,
	},
	{
		name: "Digest retrieval failure",
		podSpec: &corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Image: "nginx:latest",
				},
			},
		},
		mockDigest:       "",
		mockError:        errors.New("failed to get digest"),
		expectedImages:   []Image{},
		expectedWarnings: 1,
		expectError:      true,
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

func TestExtractContainerImagesAndPullSecretsFromPodSpec(t *testing.T) {
	for _, tt := range podSpecTestCases {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := new(MockLoader)
			mockLoader.On("GetImageDigest").Return(tt.mockDigest, tt.mockError)

			// Capture log output if needed, to verify warning messages
			// You can set up a mock logger or use a buffer to capture logs
			// Example: setup a logger to capture warning messages
			// (code omitted for brevity)

			images := extractContainerImagesAndPullSecretsFromPodSpec(tt.podSpec, mockLoader)

			if tt.expectError {
				// Assuming some logic captures warnings or errors
				// Check warning count or error messages as needed
				// This part depends on your logging setup
			} else {
				assert.Len(t, images, len(tt.expectedImages))
				for i, img := range images {
					assert.Equal(t, tt.expectedImages[i].Digest, img.Digest)
					assert.Equal(t, tt.expectedImages[i].FormattedDigest, img.FormattedDigest)
					assert.Equal(t, tt.expectedImages[i].Registry, img.Registry)
					assert.Equal(t, tt.expectedImages[i].Repository, img.Repository)
					assert.Equal(t, tt.expectedImages[i].Tag, img.Tag)
					assert.ElementsMatch(t, tt.expectedImages[i].PullSecrets, img.PullSecrets)
				}
			}
			mockLoader.AssertExpectations(t)
		})
	}
}

func createAdmissionReview(kind string, obj interface{}) v1.AdmissionReview {
	raw, _ := json.Marshal(obj)
	return v1.AdmissionReview{
		Request: &v1.AdmissionRequest{
			Kind: metav1.GroupVersionKind{Kind: kind},
			Object: runtime.RawExtension{
				Raw: raw,
			},
		},
	}
}

func TestNewImagesFromAdmissionReview(t *testing.T) {
	for _, tt := range admissionReviewTestCases {
		t.Run(tt.name, func(t *testing.T) {

			mockLoader := new(MockLoader)

			// if we expect an error, we don't need to set up the mock
			if !tt.expectError {
				mockLoader.On("GetImageDigest").Return(tt.mockDigest, tt.mockError)
			}

			images, err := NewImagesFromAdmissionReview(tt.admissionReview, mockLoader)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, images, len(tt.expectedImages))
				for i, img := range images {
					assert.Equal(t, tt.expectedImages[i].Digest, img.Digest)
					assert.Equal(t, tt.expectedImages[i].FormattedDigest, img.FormattedDigest)
					assert.Equal(t, tt.expectedImages[i].Registry, img.Registry)
					assert.Equal(t, tt.expectedImages[i].Repository, img.Repository)
					assert.Equal(t, tt.expectedImages[i].Tag, img.Tag)
					assert.ElementsMatch(t, tt.expectedImages[i].PullSecrets, img.PullSecrets)
				}
			}

			mockLoader.AssertExpectations(t)
		})
	}
}
