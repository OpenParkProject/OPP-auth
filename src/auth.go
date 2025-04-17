//go:generate oapi-codegen -include-tags=session -generate types,gin-server -o api/api.gen.go -package api api/openapi.yaml

package main

import (
	"OPP/auth/api"
	"OPP/auth/handlers"
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	ginmiddleware "github.com/oapi-codegen/gin-middleware"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/util"
)

var DEBUG_MODE = os.Getenv("DEBUG_MODE") == "true"

func main() {

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// Load OpenAPI spec for validation
	// oapi-codegen do not handle validation from the spec
	// nor authentication
	spec, err := util.LoadSwagger("api/openapi.yaml")
	if err != nil {
		log.Panicf("Failed to load OpenAPI spec: %v", err)
	}

	silenceServersWarning := false
	if DEBUG_MODE {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
		silenceServersWarning = true
	}

	// Set up the authentication function
	validatorOptions := &ginmiddleware.Options{
		SilenceServersWarning: silenceServersWarning,
	}
	validator := ginmiddleware.OapiRequestValidatorWithOptions(spec, validatorOptions)
	if err != nil {
		log.Panicf("Failed to create validator: %v", err)
	}
	r.Use(validator)
	r.SetTrustedProxies(nil)

	options := api.GinServerOptions{
		BaseURL:      "/api/v1",
		Middlewares:  nil,
		ErrorHandler: nil,
	}

	SessionHandler := handlers.NewSessionHandler()
	api.RegisterHandlersWithOptions(r, SessionHandler, options)

	fmt.Println("OPP Backend starting on :8080")
	log.Fatal(r.Run(":8080"))
}
