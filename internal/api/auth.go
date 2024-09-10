package api

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/snapp-incubator/soteria/internal/authenticator"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

// AuthRequest is the body payload structure of the auth endpoint.
type AuthRequest struct {
	Token    string `form:"token"    json:"token,omitempty"`
	Username string `from:"username" json:"username,omitempty"`
	Password string `form:"password" json:"password,omitempty"`
}

type AuthResponse struct {
	Result      string `json:"result,omitempty"`
	IsSuperuser bool   `json:"is_superuser,omitempty"`
}

// Auth is the handler responsible for authentication.
// nolint: wrapcheck
func (a API) Authv1(c *fiber.Ctx) error {
	_, span := a.Tracer.Start(c.Context(), "api.v1.auth")
	defer span.End()

	request := new(AuthRequest)

	if err := c.BodyParser(request); err != nil {
		span.RecordError(err)

		a.Logger.
			Warn("bad request",
				zap.Error(err),
			)
		authenticator.IncrementWithErrorAuthCounter("unknown_company_before_parse_body", err)

		return c.Status(http.StatusBadRequest).SendString("bad request")
	}

	vendor, token := ExtractVendorToken(request.Token, request.Username, request.Password)

	auth := a.Authenticator(vendor)

	span.SetAttributes(
		attribute.String("token", request.Token),
		attribute.String("username", request.Username),
		attribute.String("password", request.Password),
		attribute.String("authenticator", auth.GetCompany()),
	)

	err := auth.Auth(token)
	if err != nil {
		authenticator.IncrementWithErrorAuthCounter(vendor, err)
		span.RecordError(err)

		if !errors.Is(err, jwt.ErrTokenExpired) {
			a.Logger.
				Debug("auth request is not authorized",
					zap.Error(err),
					zap.String("token", request.Token),
					zap.String("username", request.Username),
					zap.String("password", request.Password),
					zap.String("authenticator", auth.GetCompany()),
				)
		}

		return c.Status(http.StatusUnauthorized).SendString("request is not authorized")
	}

	a.Logger.
		Info("auth ok",
			zap.String("token", request.Token),
			zap.String("username", request.Username),
			zap.String("password", request.Password),
			zap.String("authenticator", auth.GetCompany()),
		)
	authenticator.IncrementWithErrorAuthCounter(vendor, err)

	return c.Status(http.StatusOK).SendString("ok")
}

// Auth is the handler responsible for authentication.
// Endpoint will be used by EMQ version 5 which supports JSON on both request and response.
// https://www.emqx.io/docs/en/latest/access-control/authn/http.html
// nolint: wrapcheck, funlen
func (a API) Authv2(c *fiber.Ctx) error {
	_, span := a.Tracer.Start(c.Context(), "api.v2.auth")
	defer span.End()

	request := new(AuthRequest)

	if err := c.BodyParser(request); err != nil {
		span.RecordError(err)

		a.Logger.
			Warn("bad request",
				zap.Error(err),
			)
		authenticator.IncrementWithErrorAuthCounter("unknown_company_before_parse_body", err)

		return c.Status(http.StatusOK).JSON(AuthResponse{
			Result:      "deny",
			IsSuperuser: false,
		})
	}

	vendor, token := ExtractVendorToken(request.Token, request.Username, request.Password)

	auth := a.Authenticator(vendor)

	span.SetAttributes(
		attribute.String("token", request.Token),
		attribute.String("username", request.Username),
		attribute.String("password", request.Password),
		attribute.String("authenticator", auth.GetCompany()),
	)

	err := auth.Auth(token)
	if err != nil {
		span.RecordError(err)
		authenticator.IncrementWithErrorAuthCounter(vendor, err)

		if !errors.Is(err, jwt.ErrTokenExpired) {
			a.Logger.
				Debug("auth request is not authorized",
					zap.Error(err),
					zap.String("token", request.Token),
					zap.String("username", request.Username),
					zap.String("password", request.Password),
					zap.String("authenticator", auth.GetCompany()),
				)
		}

		return c.Status(http.StatusOK).JSON(AuthResponse{
			Result:      "deny",
			IsSuperuser: false,
		})
	}

	a.Logger.
		Info("auth ok",
			zap.String("token", request.Token),
			zap.String("username", request.Username),
			zap.String("password", request.Password),
			zap.String("authenticator", auth.GetCompany()),
		)
	authenticator.IncrementWithErrorAuthCounter(vendor, err)

	return c.Status(http.StatusOK).JSON(AuthResponse{
		Result:      "allow",
		IsSuperuser: auth.IsSuperuser(),
	})
}
