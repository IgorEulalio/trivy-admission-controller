package image

type Loader interface {
	GetImageDigest(pullString string, imagePullSecrets []string) (string, error)
}
