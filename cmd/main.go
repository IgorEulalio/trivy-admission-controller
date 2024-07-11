// main.go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/api"
	"github.com/IgorEulalio/trivy-admission-controller/pkg/logging"
)

func main() {
	logging.InitLogger()
	logger := logging.Logger()

	addr := os.Getenv("PORT")
	logger.Info().Msgf("Starting server on port %s", addr)

	http.HandleFunc("/validate", api.Validate)
	//log.Fatal(http.ListenAndServeTLS(addr, "/path/to/tls.crt", "/path/to/tls.key", nil))
	log.Fatal(http.ListenAndServe(addr, nil))
}
