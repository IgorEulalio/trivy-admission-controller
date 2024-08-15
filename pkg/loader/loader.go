package loader

type Loader interface {
	GetImageDigest(pullString string, imagePullSecrets []string) (string, error)
}
