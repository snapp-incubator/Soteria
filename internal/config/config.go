package config

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/tidwall/pretty"
	"gitlab.snapp.ir/dispatching/soteria/internal/logger"
	"gitlab.snapp.ir/dispatching/soteria/internal/topics"
	"gitlab.snapp.ir/dispatching/soteria/internal/tracing"
)

const (
	// Prefix indicates environment variables prefix.
	Prefix = "soteria_"
)

type (
	// Config is the main container of Soteria's config.
	Config struct {
		Vendors       []Vendor       `koanf:"vendors"`
		Logger        logger.Config  `koanf:"logger"`
		HTTPPort      int            `koanf:"http_port"`
		Tracer        tracing.Config `koanf:"tracer"`
		DefaultVendor string         `koanf:"default_vendor"`
	}

	Vendor struct {
		AllowedAccessTypes []string                   `koanf:"allowed_access_types"`
		Company            string                     `koanf:"company"`
		Topics             []topics.Topic             `koanf:"topics"`
		Keys               map[string][]string        `koanf:"keys"`
		IssEntityMap       map[string]string          `koanf:"iss_entity_map"`
		IssPeerMap         map[string]string          `koanf:"iss_peer_map"`
		Jwt                Jwt                        `koanf:"jwt"`
		HashIDMap          map[string]topics.HashData `koanf:"hashid_map"`
	}

	Jwt struct {
		IssName       string `koanf:"iss_name"`
		SubName       string `koanf:"sub_name"`
		SigningMethod string `koanf:"signing_method"`
	}
)

// New reads configuration with koanf.
func New() Config {
	var instance Config

	k := koanf.New(".")

	// load default configuration from file
	if err := k.Load(structs.Provider(Default(), "koanf"), nil); err != nil {
		log.Fatalf("error loading default: %s", err)
	}

	// load configuration from file
	if err := k.Load(file.Provider("config.yml"), yaml.Parser()); err != nil {
		log.Printf("error loading config.yml: %s", err)
	}

	// load environment variables
	if err := k.Load(env.Provider(Prefix, ".", func(s string) string {
		return strings.ReplaceAll(strings.ToLower(
			strings.TrimPrefix(s, Prefix)), "_", ".")
	}), nil); err != nil {
		log.Printf("error loading environment variables: %s", err)
	}

	if err := k.Unmarshal("", &instance); err != nil {
		log.Fatalf("error unmarshalling config: %s", err)
	}

	indent, err := json.MarshalIndent(instance, "", "\t")
	if err != nil {
		log.Fatalf("error marshaling configuration to json: %s", err)
	}

	indent = pretty.Color(indent, nil)
	tmpl := `
	================ Loaded Configuration ================
	%s
	======================================================
	`
	log.Printf(tmpl, string(indent))

	return instance
}
