package config

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/snapp-incubator/soteria/internal/logger"
	"github.com/snapp-incubator/soteria/internal/topics"
	"github.com/snapp-incubator/soteria/internal/tracing"
	"github.com/tidwall/pretty"
)

const (
	// Prefix indicates environment variables prefix.
	Prefix = "soteria_"
)

type (
	// Config is the main container of Soteria's config.
	Config struct {
		Vendors              []Vendor             `json:"vendors,omitempty"                 koanf:"vendors"`
		Logger               logger.Config        `json:"logger,omitempty"                  koanf:"logger"`
		HTTPPort             int                  `json:"http_port,omitempty"               koanf:"http_port"`
		Tracer               tracing.Config       `json:"tracer,omitempty"                  koanf:"tracer"`
		DefaultVendor        string               `json:"default_vendor,omitempty"          koanf:"default_vendor"`
		Validator            Validator            `json:"validator,omitempty"               koanf:"validator"`
		BlackListUserLogging BlackListUserLogging `json:"black_list_user_logging,omitempty" koanf:"black_list_user_logging"`
	}

	Vendor struct {
		AllowedAccessTypes []string                   `json:"allowed_access_types,omitempty" koanf:"allowed_access_types"`
		Company            string                     `json:"company,omitempty"              koanf:"company"`
		Topics             []topics.Topic             `json:"topics,omitempty"               koanf:"topics"`
		Keys               map[string]string          `json:"keys,omitempty"                 koanf:"keys"`
		IssEntityMap       map[string]string          `json:"iss_entity_map,omitempty"       koanf:"iss_entity_map"`
		IssPeerMap         map[string]string          `json:"iss_peer_map,omitempty"         koanf:"iss_peer_map"`
		Jwt                JWT                        `json:"jwt,omitempty"                  koanf:"jwt"`
		Type               string                     `json:"type,omitempty"                 koanf:"type"`
		HashIDMap          map[string]topics.HashData `json:"hash_id_map,omitempty"          koanf:"hashid_map"`
	}

	JWT struct {
		IssName       string `json:"iss_name,omitempty"       koanf:"iss_name"`
		SubName       string `json:"sub_name,omitempty"       koanf:"sub_name"`
		SigningMethod string `json:"signing_method,omitempty" koanf:"signing_method"`
	}

	Validator struct {
		URL     string        `json:"url,omitempty"     koanf:"url"`
		Timeout time.Duration `json:"timeout,omitempty" koanf:"timeout"`
	}

	BlackListUserLogging struct {
		Iss     int   `json:"iss,omitempty"      koanf:"iss"`
		UserIDs []int `json:"user_ids,omitempty" koanf:"user_ids"`
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
