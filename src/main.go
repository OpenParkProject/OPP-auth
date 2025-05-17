//go:generate oapi-codegen -include-tags=session,user -generate types,gin-server -o api/api.gen.go -package api api/openapi.yaml

package main

import (
	"OPP/auth/api"
	"OPP/auth/auth"
	"OPP/auth/db"
	"OPP/auth/handlers"
	"OPP/auth/rbac"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gin-gonic/gin"
	ginmiddleware "github.com/oapi-codegen/gin-middleware"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/util"
)

var DEBUG_MODE = os.Getenv("DEBUG_MODE")

type opp_handlers struct {
	handlers.SessionHandlers
	handlers.UserHandlers
}

func main() {

	rbac := rbac.SetupRBAC()
	if rbac == nil {
		log.Panicf("Failed to setup RBAC")
	}

	if err := db.Init(); err != nil {
		log.Panicf("Failed to initialize database: %v", err)
	}
	if db.GetDB() == nil {
		log.Panicf("Failed to get database instance")
	} else {
		defer db.GetDB().Close()
	}

	opp_auth_handlers := &opp_handlers{
		SessionHandlers: *handlers.NewSessionHandler(),
		UserHandlers:    *handlers.NewUserHandler(),
	}

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
	if DEBUG_MODE == "true" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
		silenceServersWarning = true
	}

	// Set up the authentication function
	validatorOptions := &ginmiddleware.Options{
		Options: openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
				return auth.AuthenticationFunc(ctx, input)
			},
		},
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

	api.RegisterHandlersWithOptions(r, opp_auth_handlers, options)

	fmt.Println("OPP Auth starting on :8090")
	log.Fatal(r.Run(":8090"))
}
