package cmd

import (
	"fmt"
	"log"
	"net/http"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/api"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/cache"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/config"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/kubernetes"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
)

func Run() {

	logging.InitLogger()
	logger := logging.Logger()

	config.InitConfig()

	c, err := cache.NewCacheFromConfig(config.Cfg)
	if err != nil {
		logger.Fatal().Msgf("Error creating cache: %v", err)
	}

	err = kubernetes.Init()
	if err != nil {
		logger.Fatal().Msgf("Error creating kubernetes client: %v", err)
	}

	handler := api.NewHandler(c, kubernetes.GetClient())

	http.HandleFunc("/validate", handler.Validate)
	logger.Info().Msgf("Starting server on port %v", config.Cfg.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%v", "127.0.0.1", config.Cfg.Port), nil))
}
