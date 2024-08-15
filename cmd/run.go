package cmd

import (
	"fmt"
	"log"
	"net/http"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/api"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/cache"
	configuration "github.com/IgorEulalio/trivy-admission-controller/pkg/config"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/datastore"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/kubernetes"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/loader"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/scan"
)

func Run() {

	logging.InitLogger()
	logger := logging.Logger()

	configuration.InitConfig()
	config := configuration.Cfg
	logger.Debug().Msg("Config successfully loaded.")
	c, err := cache.NewCacheFromConfig(config)
	if err != nil {
		logger.Fatal().Msgf("Error creating cache: %v", err)
	}

	err = kubernetes.Init()
	if err != nil {
		logger.Fatal().Msgf("Error creating kubernetes client: %v", err)
	}

	remoteLoader := loader.NewLoader()
	scanner, err := scan.NewTrivyScanner(new(scan.DefaultCommandRunner), scan.GetTrivyResultFromFileSystem)
	if err != nil {
		logger.Fatal().Msgf("Error creating trivy scanner: %v", err)
	}

	validateHandler, err := api.NewValidateHandler(scanner, remoteLoader, datastore.NewEtcdAndCacheDataStore(kubernetes.GetClient(), c))
	if err != nil {
		logger.Fatal().Msgf("Error creating validateHandler: %v", err)
	}

	scanHandler, err := api.NewScanHandler(remoteLoader, datastore.NewEtcdAndCacheDataStore(kubernetes.GetClient(), c))
	if err != nil {
		logger.Fatal().Msgf("Error creating scanHandler: %v", err)
	}

	http.HandleFunc("/validate", validateHandler.Validate)
	http.HandleFunc("/scan", scanHandler.Scan)
	logger.Info().Msgf("Starting server on port %v, using certificate file %v and certificate key %v", config.Port, config.CertFile, config.KeyFile)
	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("%s:%v", "0.0.0.0", config.Port), config.CertFile, config.KeyFile, nil))
}
