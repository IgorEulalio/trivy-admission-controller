package loader

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/kubernetes"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	azure "github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1 "k8s.io/api/core/v1"
)

// DockerConfig represents the structure of the docker config JSON.
type DockerConfig struct {
	Auths map[string]DockerAuth `json:"auths"`
}

// DockerAuth represents the auth structure within the docker config.
type DockerAuth struct {
	Auth string `json:"auth"`
}

type RemoteLoader struct {
	config loaderConfig
}

type loaderConfig struct {
	insecureSkipTLSVerify bool
}

// todo - implement options pattern for new loader
func NewLoader() RemoteLoader {
	return RemoteLoader{
		config: loaderConfig{
			insecureSkipTLSVerify: false,
		},
	}
}

func (l RemoteLoader) GetImageDigest(pullString string, imagePullSecrets []string) (string, error) {
	logger := logging.Logger()

	ref, err := name.ParseReference(pullString)
	if err != nil {
		return "", err
	}

	var kcs []authn.Keychain

	var remoteOpts []remote.Option

	kcs = []authn.Keychain{
		authn.DefaultKeychain,
		authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard))),
		authn.NewKeychainFromHelper(azure.NewACRCredentialsHelper()),
		// google requires gcloud/gcr adapter to be present on FS - that's why we embed it in the container - TODO
		google.Keychain,
	}
	remoteOpts = append(remoteOpts, remote.WithAuthFromKeychain(authn.NewMultiKeychain(kcs...)))

	remoteOpts = append(remoteOpts, remote.WithTransport(
		&http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: l.config.insecureSkipTLSVerify},
		},
	))

	if len(imagePullSecrets) > 0 {
		username, password, err := l.GetIdentityFromSecret(imagePullSecrets)
		if err != nil {
			logger.Warn().Msgf("error fetching secrets, defaulting to default keychain, acr helper, ecr helper or gcr keychain: %v", err)
		} else {
			basicAuth := &authn.Basic{
				Username: username,
				Password: password,
			}

			remoteOpts = append(remoteOpts, remote.WithAuth(basicAuth))
		}
	}

	img, err := remote.Image(ref, remoteOpts...)
	if err != nil {
		return "", err
	}

	digest, err := img.Digest()
	if err != nil {
		return "", err
	}
	logger.Debug().Msgf("image  %v digest: %v", pullString, digest.String())

	return digest.String(), nil
}

func (l RemoteLoader) GetIdentityFromSecret(pullSecrets []string) (string, string, error) {
	var lastErr error
	var username, password string
	for _, pullSecret := range pullSecrets {
		secret, err := kubernetes.GetClient().GetSecret("default", pullSecret)
		if err != nil {
			lastErr = err
			continue
		}
		username, password, err = getUserNamePasswordFromSecret(secret)
		if err != nil {
			lastErr = err
			continue
		}
		if err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
			continue
		}
	}

	return username, password, lastErr
}

// getUserNamePasswordFromSecret extracts the username and password from the Kubernetes secret.
func getUserNamePasswordFromSecret(secret *v1.Secret) (string, string, error) {
	data, ok := secret.Data[".dockerconfigjson"]
	if !ok {
		return "", "", fmt.Errorf("secret is not of type .dockerconfigjson")
	}

	var dockerConfig DockerConfig
	if err := json.Unmarshal(data, &dockerConfig); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal docker config: %w", err)
	}

	for _, auth := range dockerConfig.Auths {
		decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode auth field: %w", err)
		}

		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid auth field format")
		}

		return parts[0], parts[1], nil
	}

	return "", "", fmt.Errorf("no auth field found in docker config")
}
