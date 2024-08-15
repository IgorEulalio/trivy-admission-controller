package datastore_test

import (
	"errors"
	"testing"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/datastore"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type MockCache struct {
	mock.Mock
}

func (m *MockCache) Set(key string, value interface{}, expiration time.Duration) error {
	args := m.Called(key, value, expiration)
	return args.Error(0)
}

func (m *MockCache) Get(key string) (interface{}, bool) {
	args := m.Called(key)
	return args.Get(0), args.Bool(1)
}

func (m *MockCache) Delete(key string) error {
	args := m.Called(key)
	return args.Error(0)
}

type MockKubernetesClient struct {
	mock.Mock
}

func (m *MockKubernetesClient) GetSecret(namespace, secretName string) (*v1.Secret, error) {
	args := m.Called(namespace, secretName)
	return args.Get(0).(*v1.Secret), args.Error(1)
}

func (m *MockKubernetesClient) GetResource(gvr schema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error) {
	args := m.Called(gvr, namespace, name)
	return args.Get(0).(*unstructured.Unstructured), args.Error(1)
}

type GetImageFromDataStoreTestCase struct {
	name             string
	image            image.Image
	cacheReturn      interface{}
	cachePresent     bool
	kubernetesReturn *unstructured.Unstructured
	kubernetesError  error
	expectedImage    *image.Image
	expectedError    bool
}

var getImageFromDataStoreTestCases = []GetImageFromDataStoreTestCase{
	{
		name:          "Image found in cache - allowed",
		image:         image.Image{PullString: "nginx:latest", Digest: "sha256:abcd1234", FormattedDigest: "sha256-abcd1234"},
		cacheReturn:   "true",
		cachePresent:  true,
		expectedImage: &image.Image{PullString: "nginx:latest", Digest: "sha256:abcd1234", FormattedDigest: "sha256-abcd1234", Allowed: true},
		expectedError: false,
	},
	{
		name:          "Image found in cache - denied",
		image:         image.Image{PullString: "nginx:latest", Digest: "sha256:abcd1234", FormattedDigest: "sha256-abcd1234"},
		cacheReturn:   "false",
		cachePresent:  true,
		expectedImage: &image.Image{PullString: "nginx:latest", Digest: "sha256:abcd1234", FormattedDigest: "sha256-abcd1234", Allowed: false},
		expectedError: false,
	},
	{
		name:         "Image not in cache, found in Kubernetes store",
		image:        image.Image{PullString: "nginx:latest", Digest: "sha256:abcd1234", FormattedDigest: "sha256-abcd1234"},
		cacheReturn:  nil,
		cachePresent: false,
		kubernetesReturn: &unstructured.Unstructured{
			Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"allowed": true,
				},
			},
		},
		expectedImage: &image.Image{PullString: "nginx:latest", Digest: "sha256:abcd1234", FormattedDigest: "sha256-abcd1234", Allowed: true},
		expectedError: false,
	},
	{
		name:             "Image not in cache, not found in Kubernetes store",
		image:            image.Image{PullString: "nginx:latest", Digest: "sha256:abcd1234", FormattedDigest: "sha256-abcd1234"},
		cacheReturn:      nil,
		cachePresent:     false,
		kubernetesReturn: nil,
		kubernetesError:  errors.New("not found"),
		expectedImage:    &image.Image{PullString: "nginx:latest", Digest: "sha256:abcd1234", FormattedDigest: "sha256-abcd1234", Allowed: false},
		expectedError:    true,
	},
}

func TestGetImageFromDataStore(t *testing.T) {
	for _, tt := range getImageFromDataStoreTestCases {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(MockCache)
			mockClient := new(MockKubernetesClient)
			dataStore := datastore.NewEtcdAndCacheDataStore(mockClient, mockCache)

			// Mock the cache behavior
			mockCache.On("Get", tt.image.FormattedDigest).Return(tt.cacheReturn, tt.cachePresent)

			// Mock the Kubernetes client behavior if the image is not in cache
			if !tt.cachePresent {
				mockClient.On("GetResource", mock.Anything, mock.Anything, mock.Anything).Return(tt.kubernetesReturn, tt.kubernetesError)
			}

			// Call the method under test
			imageFromDataStore, err := dataStore.GetImageFromDataStore(tt.image)

			// Validate the results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedImage, imageFromDataStore)

			// Assert that the mocks were called as expected
			mockCache.AssertExpectations(t)
			if !tt.cachePresent {
				mockClient.AssertExpectations(t)
			}
		})
	}
}
