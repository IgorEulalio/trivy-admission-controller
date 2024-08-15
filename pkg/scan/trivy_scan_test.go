package scan_test

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/image"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

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

func newTestTrivyScanner(runner scan.Runner, readResultFunc func(path string) (*result.ScanResult, error)) *scan.TrivyScanner {
	return &scan.TrivyScanner{
		OutputDir:      "./test-output",
		ScannerModes:   []string{"vuln"},
		Runner:         runner,
		ReadResultFunc: readResultFunc,
	}
}

func TestTrivyScannerScan(t *testing.T) {
	for _, tt := range trivyScannerTestCases {
		t.Run(tt.name, func(t *testing.T) {
			mockCommandRunner := new(MockCommandRunner)

			mockCommandRunner.On("Run", "sh", "-c", mock.Anything).Return(tt.mockExecCmd)
			mockCommandRunner.On("RunCommand", mock.Anything).Return(tt.runCommandError)

			scanner := newTestTrivyScanner(mockCommandRunner, tt.mockReadResultFunc)

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
