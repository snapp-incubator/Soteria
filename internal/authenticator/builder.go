package authenticator

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/snapp-incubator/soteria/internal/config"
	"github.com/snapp-incubator/soteria/internal/topics"
	"github.com/snapp-incubator/soteria/pkg/acl"
	"github.com/snapp-incubator/soteria/pkg/validator"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var (
	ErrAdminAuthenticatorSystemKey = errors.New("admin authenticator supports only one key named system")
	ErrNoAuthenticator             = errors.New("at least one vendor should be enable to have soteria")
	ErrNoDefaultCaseIssEntity      = errors.New("default case for iss-entity map is required")
	ErrNoDefaultCaseIssPeer        = errors.New("default case for iss-peer map is required")
	ErrInvalidAuthenticator        = errors.New("there is no authenticator to support your request")
)

type Builder struct {
	Vendors                    []config.Vendor
	Logger                     *zap.Logger
	ValidatorConfig            config.Validator
	Tracer                     trace.Tracer
	BlackListUserLoggingConfig config.BlackListUserLogging
}

func (b Builder) Authenticators() (map[string]Authenticator, error) {
	all := make(map[string]Authenticator)

	for _, vendor := range b.Vendors {
		var (
			auth Authenticator
			err  error
		)

		switch vendor.Type {
		case "auto", "validator", "validator-based", "using-validator":
			auth, err = b.autoAuthenticator(vendor, b.BlackListUserLoggingConfig)
			if err != nil {
				return nil, fmt.Errorf("cannot build auto authenticator %w", err)
			}
		case "admin", "internal":
			auth, err = b.adminAuthenticator(vendor)
			if err != nil {
				return nil, fmt.Errorf("cannot build admin authenticator %w", err)
			}
		case "manual":
			auth, err = b.manualAuthenticator(vendor)
			if err != nil {
				return nil, fmt.Errorf("cannot build manual authenticator %w", err)
			}
		default:
			return nil, ErrInvalidAuthenticator
		}

		all[vendor.Company] = auth
	}

	if len(all) == 0 {
		return nil, ErrNoAuthenticator
	}

	return all, nil
}

func (b Builder) adminAuthenticator(vendor config.Vendor) (*AdminAuthenticator, error) {
	if _, ok := vendor.Keys["system"]; !ok || len(vendor.Keys) != 1 {
		return nil, ErrAdminAuthenticatorSystemKey
	}

	keys, err := b.GenerateKeys(vendor.Jwt.SigningMethod, vendor.Keys)
	if err != nil {
		return nil, fmt.Errorf("loading keys failed %w", err)
	}

	return &AdminAuthenticator{
		Key:       keys["system"],
		Company:   vendor.Company,
		JwtConfig: vendor.Jwt,
		Parser:    jwt.NewParser(),
	}, nil
}

func (b Builder) manualAuthenticator(vendor config.Vendor) (*ManualAuthenticator, error) {
	if err := b.ValidateMappers(vendor.IssEntityMap, vendor.IssPeerMap); err != nil {
		return nil, fmt.Errorf("failed to validate mappers %w", err)
	}

	allowedAccessTypes, err := b.GetAllowedAccessTypes(vendor.AllowedAccessTypes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse allowed access types %w", err)
	}

	hid, err := topics.NewHashIDManager(vendor.HashIDMap)
	if err != nil {
		return nil, fmt.Errorf("cannot create hash-id manager %w", err)
	}

	keys, err := b.GenerateKeys(vendor.Jwt.SigningMethod, vendor.Keys)
	if err != nil {
		return nil, fmt.Errorf("loading keys failed %w", err)
	}

	return &ManualAuthenticator{
		Keys:               keys,
		AllowedAccessTypes: allowedAccessTypes,
		Company:            vendor.Company,
		TopicManager: topics.NewTopicManager(
			vendor.Topics,
			hid,
			vendor.Company,
			vendor.IssEntityMap,
			vendor.IssPeerMap,
			b.Logger.Named("topic-manager"),
		),
		JWTConfig: vendor.Jwt,
		Parser:    jwt.NewParser(jwt.WithValidMethods([]string{vendor.Jwt.SigningMethod})),
	}, nil
}

func (b Builder) autoAuthenticator(vendorCfg config.Vendor, blackListUserLoggingCfg config.BlackListUserLogging) (
	*AutoAuthenticator, error,
) {
	allowedAccessTypes, err := b.GetAllowedAccessTypes(vendorCfg.AllowedAccessTypes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse allowed access types %w", err)
	}

	hid, err := topics.NewHashIDManager(vendorCfg.HashIDMap)
	if err != nil {
		return nil, fmt.Errorf("cannot create hash-id manager %w", err)
	}

	client := validator.New(b.ValidatorConfig.URL, b.ValidatorConfig.Timeout)

	return &AutoAuthenticator{
		AllowedAccessTypes: allowedAccessTypes,
		Company:            vendorCfg.Company,
		TopicManager: topics.NewTopicManager(
			vendorCfg.Topics,
			hid,
			vendorCfg.Company,
			vendorCfg.IssEntityMap,
			vendorCfg.IssPeerMap,
			b.Logger.Named("topic-manager"),
		),
		Tracer:    b.Tracer,
		JWTConfig: vendorCfg.Jwt,
		Validator: client,
		Parser:    jwt.NewParser(),
		Logger:    b.Logger.Named("auto-authenticator"),
		blackList: newAutoBlackListChecker(blackListUserLoggingCfg),
	}, nil
}

// GetAllowedAccessTypes will return all allowed access types in Soteria.
func (b Builder) GetAllowedAccessTypes(accessTypes []string) ([]acl.AccessType, error) {
	allowedAccessTypes := make([]acl.AccessType, 0, len(accessTypes))

	for _, a := range accessTypes {
		at, err := toUserAccessType(a)
		if err != nil {
			return nil, fmt.Errorf("could not convert %s: %w", at, err)
		}

		allowedAccessTypes = append(allowedAccessTypes, at)
	}

	return allowedAccessTypes, nil
}

// toUserAccessType will convert string access type to it's own type.
func toUserAccessType(access string) (acl.AccessType, error) {
	switch access {
	case "pub", "publish":
		return acl.Pub, nil
	case "sub", "subscribe":
		return acl.Sub, nil
	case "pubsub", "subpub":
		return acl.PubSub, nil
	}

	return "", ErrInvalidAccessType
}

func (b Builder) ValidateMappers(issEntityMap, issPeerMap map[string]string) error {
	if _, ok := issEntityMap[topics.Default]; !ok {
		return ErrNoDefaultCaseIssEntity
	}

	if _, ok := issPeerMap[topics.Default]; !ok {
		return ErrNoDefaultCaseIssPeer
	}

	return nil
}
