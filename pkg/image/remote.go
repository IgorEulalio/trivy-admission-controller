package image

import (
	"github.com/IgorEulalio/trivy-admission-controller/pkg/loader"
)

type RemoteLoader struct {
	pullString  string
	pullSecrets []string
}

func (rl RemoteLoader) GetImageDigest(pullString string, pullSecrets []string) (string, error) {
	loader := loader.NewLoader(pullString, pullSecrets)
	digest, err := loader.GetImageDigest()
	if err != nil {
		return "", err
	}
	return digest, nil
}
