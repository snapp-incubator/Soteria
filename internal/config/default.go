package config

import (
	"time"

	"github.com/snapp-incubator/soteria/internal/logger"
	"github.com/snapp-incubator/soteria/internal/topics"
	"github.com/snapp-incubator/soteria/internal/tracing"
	"github.com/snapp-incubator/soteria/pkg/acl"
)

const (
	DefaultHTTPPort            = 9999
	DefaultDriverHashLength    = 15
	DefaultPassengerHashLength = 15
)

// Default return default configuration.
// nolint: mnd
func Default() Config {
	return Config{
		DefaultVendor: "snapp",
		Vendors: []Vendor{
			SnappVendor(),
		},
		Logger: logger.Config{
			Level:      "debug",
			Stacktrace: true,
		},
		HTTPPort: DefaultHTTPPort,
		Tracer: tracing.Config{
			Enabled:  false,
			Ratio:    0.1,
			Endpoint: "127.0.0.1:4317",
		},
		Validator: Validator{
			URL:     "http://validator-lb",
			Timeout: 5 * time.Second,
		},
		BlackListUserLogging: BlackListUserLogging{
			Iss:     0,
			UserIDs: []int{},
		},
	}
}

// nolint: funlen
func SnappVendor() Vendor {
	return Vendor{
		Type: "manual",
		AllowedAccessTypes: []string{
			"pub",
			"sub",
		},
		HashIDMap: map[string]topics.HashData{
			"0": {
				Alphabet: "",
				Length:   DefaultDriverHashLength,
				Salt:     "secret",
			},
			"1": {
				Alphabet: "",
				Length:   DefaultPassengerHashLength,
				Salt:     "secret",
			},
		},
		Company: "snapp",
		Topics: []topics.Topic{
			{
				Type:     topics.CabEvent,
				Template: "^{{IssToEntity .iss}}-event-{{ EncodeMD5 (DecodeHashID .sub .iss) }}$",
				Accesses: map[string]acl.AccessType{
					topics.DriverIss:    acl.Sub,
					topics.PassengerIss: acl.Sub,
				},
			},
			{
				Type:     topics.DriverLocation,
				Template: "^{{.company}}/driver/{{.sub}}/location$",
				Accesses: map[string]acl.AccessType{
					topics.DriverIss:    acl.Pub,
					topics.PassengerIss: acl.None,
				},
			},
			{
				Type:     topics.PassengerLocation,
				Template: "^{{.company}}/passenger/{{.sub}}/location$",
				Accesses: map[string]acl.AccessType{
					topics.DriverIss:    acl.Pub,
					topics.PassengerIss: acl.Pub,
				},
			},
			{
				Type:     topics.SuperappEvent,
				Template: "^{{.company}}/{{IssToEntity .iss}}/{{.sub}}/superapp$",
				Accesses: map[string]acl.AccessType{
					topics.DriverIss:    acl.Sub,
					topics.PassengerIss: acl.Sub,
				},
			},
			{
				Type:     topics.BoxEvent,
				Template: "^bucks$",
				Accesses: map[string]acl.AccessType{
					topics.DriverIss:    acl.None,
					topics.PassengerIss: acl.None,
				},
			},
			{
				Type:     topics.SharedLocation,
				Template: "^{{.company}}/{{IssToEntity .iss}}/{{.sub}}/{{IssToPeer .iss}}-location$", //nolint:lll
				Accesses: map[string]acl.AccessType{
					topics.DriverIss:    acl.Sub,
					topics.PassengerIss: acl.Sub,
				},
			},
			{
				Type:     topics.Chat,
				Template: "^{{.company}}/{{IssToEntity .iss}}/{{.sub}}/chat$",
				Accesses: map[string]acl.AccessType{
					topics.DriverIss:    acl.Sub,
					topics.PassengerIss: acl.Sub,
				},
			},
			{
				Type:     topics.GeneralCallEntry,
				Template: "^shared/{{.company}}/{{IssToEntity .iss}}/{{.sub}}/call/send$",
				Accesses: map[string]acl.AccessType{
					topics.DriverIss:    acl.Pub,
					topics.PassengerIss: acl.Pub,
				},
			},
			{
				Type:     topics.NodeCallEntry,
				Template: "^{{.company}}/{{IssToEntity .iss}}/{{.sub}}/call/[a-zA-Z0-9-_]+/send$", //nolint: lll
				Accesses: map[string]acl.AccessType{
					topics.DriverIss:    acl.Pub,
					topics.PassengerIss: acl.Pub,
				},
			},
			{
				Type:     topics.CallOutgoing,
				Template: "^{{.company}}/{{IssToEntity .iss}}/{{.sub}}/call/receive$",
				Accesses: map[string]acl.AccessType{
					topics.DriverIss:    acl.Sub,
					topics.PassengerIss: acl.Sub,
				},
			},
		},
		Keys: map[string]string{
			"0": `-----BEGIN PUBLIC KEY-----
			MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyG4XpV9TpDfgWJF9TiIv
			va4hNhDuqYMJO6iXLzr3y8oCvoB7zUK0EjtbLH+A3gr1kUvyZKDWT4qHTvU2Sshm
			X+ttWGK34EhCvF3Lb18yxmVDSSK8JIcTaJjMqmyubxzamQnNoWazJ7ea9BIo2YGL
			C9rgPbi1hihhdb07xPGUkJRqbWkI98xjDhKdMqiwW1hIRXm/apo++FjptvqvF84s
			ynC5gWGFHiGNICRsLJBczLEAf2Atbafigq6/tovzMabnp2yRtr1ReEgioH1RO4gX
			J7F4N5f6y/VWd8+sDOSxtS/HcnP/7g8/A54G2IbXxr+EiwOO/1F+pyMPKq7sGDSU
			DwIDAQAB
-----END PUBLIC KEY-----`,

			"1": `-----BEGIN PUBLIC KEY-----
			MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5SeRfOdTyvQZ7N9ahFHl
        +J05r7e9fgOQ2cpOtnnsIjAjCt1dF7/NkqVifEaxABRBGG9iXIw//G4hi0TqoKqK
        aoSHMGf6q9pSRLGyB8FatxZf2RBTgrXYqVvpasbnB1ZNv858yTpRjV9NzJXYHLp8
        8Hbd/yYTR6Q7ajs11/SMLGO7KBELsI1pBz7UW/fngJ2pRmd+RkG+EcGrOIZ27TkI
        Xjtog6bgfmtV9FWxSVdKACOY0OmW+g7jIMik2eZTYG3kgCmW2odu3zRoUa7l9VwN
        YMuhTePaIWwOifzRQt8HDsAOpzqJuLCoYX7HmBfpGAnwu4BuTZgXVwpvPNb+KlgS
        pQIDAQAB
-----END PUBLIC KEY-----`,
		},
		IssEntityMap: map[string]string{
			"0":       "driver",
			"1":       "passenger",
			"default": "",
		},
		IssPeerMap: map[string]string{
			"0":       "passenger",
			"1":       "driver",
			"default": "",
		},
		Jwt: JWT{
			IssName:       "iss",
			SubName:       "sub",
			SigningMethod: "RS512",
		},
	}
}
