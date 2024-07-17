package cmd

import (
	"fmt"
	"log"
	"net/http"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/api"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/cache"
	configuration "github.com/IgorEulalio/trivy-admission-controller/pkg/config"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/kubernetes"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
)

func Run() {

	logging.InitLogger()
	logger := logging.Logger()

	configuration.InitConfig()
	config := configuration.Cfg

	c, err := cache.NewCacheFromConfig(config)
	if err != nil {
		logger.Fatal().Msgf("Error creating cache: %v", err)
	}

	err = kubernetes.Init()
	if err != nil {
		logger.Fatal().Msgf("Error creating kubernetes client: %v", err)
	}

	handler := api.NewHandler(c, kubernetes.GetClient())

	http.HandleFunc("/validate", handler.Validate)
	logger.Info().Msgf("Starting server on port %v", config.Port)
	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf("%s:%v", "0.0.0.0", config.Port), config.CertFile, config.KeyFile, nil))
}
