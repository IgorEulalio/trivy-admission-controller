package scan_test

import (
	"errors"
	"os/exec"
	"testing"
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/cache"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/image"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/kubernetes"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type MockCache struct {
	mock.Mock
}

func (m *MockCache) Set(key string, value interface{}, expiration time.Duration) error {
	return nil
}

func (m *MockCache) Get(key string) (interface{}, bool) {
	return nil, false
}

func (m *MockCache) Delete(key string) error {
	return nil
}

type MockKubernetesClient struct {
	mock.Mock
}

func (m *MockKubernetesClient) GetSecret(namespace, secretName string) (*v1.Secret, error) {
	return &v1.Secret{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{},
		Immutable:  nil,
		Data:       nil,
		StringData: nil,
		Type:       "",
	}, nil
}

func (m *MockKubernetesClient) GetResource(gvr schema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error) {
	return nil, nil
}

type MockCommandRunner struct {
	mock.Mock
}

func (m *MockCommandRunner) Run(name string, arg ...string) *exec.Cmd {
	args := make([]interface{}, len(arg))
	for i, v := range arg {
		args[i] = v
	}
	allArgs := append([]interface{}{name}, args...)
	return m.Called(allArgs...).Get(0).(*exec.Cmd)
}

func (m *MockCommandRunner) RunCommand(cmd *exec.Cmd) error {
	return m.Called(cmd).Error(0)
}

type trivyScannerTestCase struct {
	name               string
	imagesToBeScanned  []image.Image
	mockCommandError   error
	expectedResults    []result.ScanResult
	expectedError      bool
	mockExecCmd        *exec.Cmd
	runCommandError    error
	mockReadResultFunc func(path string) (*result.ScanResult, error)
}

// Define the test cases as a reusable slice
var trivyScannerTestCases = []trivyScannerTestCase{
	{
		name: "Successful scan of a single image",
		imagesToBeScanned: []image.Image{
			{
				PullString: "nginx:latest",
			},
		},
		expectedResults: []result.ScanResult{
			{
				ArtifactName: "nginx:latest",
			},
		},
		expectedError: false,
		mockExecCmd: &exec.Cmd{
			Path: "/my-mock/path",
			Dir:  "/my-mock/dir",
		},
		runCommandError: nil,
		mockReadResultFunc: func(path string) (*result.ScanResult, error) {
			return &result.ScanResult{
				SchemaVersion: 0,
				ArtifactName:  "nginx:latest",
			}, nil
		},
	},
	{
		name: "Successful scan of two images",
		imagesToBeScanned: []image.Image{
			{
				PullString: "nginx:latest",
			},
			{
				PullString: "nginx:latest",
			},
		},
		expectedResults: []result.ScanResult{
			{
				ArtifactName: "nginx:latest",
			},
			{
				ArtifactName: "nginx:latest",
			},
		},
		expectedError: false,
		mockExecCmd: &exec.Cmd{
			Path: "/my-mock/path",
			Dir:  "/my-mock/dir",
		},
		runCommandError: nil,
		mockReadResultFunc: func(path string) (*result.ScanResult, error) {
			return &result.ScanResult{
				SchemaVersion: 0,
				ArtifactName:  "nginx:latest",
			}, nil
		},
	},
	{
		name: "Error scan of a single image",
		imagesToBeScanned: []image.Image{
			{
				PullString: "nginx:latest",
			},
		},
		expectedResults: nil,
		expectedError:   true,
		mockExecCmd: &exec.Cmd{
			Path:   "/my-mock/path",
			Dir:    "/my-mock/dir",
			Stderr: nil,
			Stdout: nil,
		},
		runCommandError: errors.New("error executing trivy scan"),
		mockReadResultFunc: func(path string) (*result.ScanResult, error) {
			return &result.ScanResult{
				SchemaVersion: 0,
				ArtifactName:  "nginx:latest",
			}, nil
		},
	},
}

func newTestTrivyScanner(cache cache.Cache, client kubernetes.Client, runner scan.Runner, readResultFunc func(path string) (*result.ScanResult, error)) *scan.TrivyScanner {
	return &scan.TrivyScanner{
		OutputDir:        "./test-output",
		ScannerModes:     []string{"vuln"},
		Cache:            cache,
		KubernetesClient: client,
		Runner:           runner,
		ReadResultFunc:   readResultFunc,
	}
}

func TestTrivyScannerScan(t *testing.T) {
	for _, tt := range trivyScannerTestCases {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := new(MockCache)
			mockClient := new(MockKubernetesClient)
			mockCommandRunner := new(MockCommandRunner)

			mockCommandRunner.On("Run", "sh", "-c", mock.Anything).Return(tt.mockExecCmd)
			mockCommandRunner.On("RunCommand", mock.Anything).Return(tt.runCommandError)

			scanner := newTestTrivyScanner(mockCache, mockClient, mockCommandRunner, tt.mockReadResultFunc)

			results, err := scanner.Scan(tt.imagesToBeScanned)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResults, results)
				assert.Equal(t, len(tt.imagesToBeScanned), len(results))
			}

			mockCommandRunner.AssertExpectations(t)
		})
	}
}
