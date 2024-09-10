package authenticator

import (
	"context"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/snapp-incubator/soteria/internal/config"
	"github.com/snapp-incubator/soteria/internal/topics"
	"github.com/snapp-incubator/soteria/pkg/acl"
	"github.com/snapp-incubator/soteria/pkg/validator"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// AutoAuthenticator is responsible for Acl/Auth/Token of users.
type AutoAuthenticator struct {
	AllowedAccessTypes []acl.AccessType
	TopicManager       *topics.Manager
	Company            string
	JWTConfig          config.JWT
	Validator          validator.Client
	Parser             *jwt.Parser
	Tracer             trace.Tracer
	Logger             *zap.Logger
	blackList          autoBlackListChecker
}

// Auth check user authentication by checking the user's token
// isSuperuser is a flag that authenticator set it true when credentials is related to a superuser.
func (a AutoAuthenticator) Auth(tokenString string) error {
	ctx, span := a.Tracer.Start(context.Background(), "auto-authenticator.auth")
	span.End()

	headers := http.Header{
		validator.ServiceNameHeader: []string{"soteria"},
		"user-agent":                []string{},
		"X-APP-Version-Code":        []string{""},
		"X-APP-Version":             []string{""},
		"X-APP-Name":                []string{"soteria"},
		"locale":                    []string{"en-US"},
	}

	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(headers))

	payload, err := a.Validator.Validate(ctx, headers, "bearer "+tokenString)
	if err != nil {
		return fmt.Errorf("token is invalid: %w", err)
	}

	if a.blackList.isBlackList(payload.UserID, payload.Iss) {
		a.Logger.Warn("blacklisted user is requesting!",
			zap.Int("iat", payload.IAT),
			zap.String("aud", payload.Aud),
			zap.Int("iss", payload.Iss),
			zap.String("sub", payload.Sub),
			zap.Int("user_id", payload.UserID),
			zap.String("email", payload.Email),
			zap.Int("exp", payload.Exp),
			zap.String("locale", payload.Locale),
			zap.String("sid", payload.Sid),
		)
	}

	return nil
}

// ACL check a user access to a topic.
// nolint: funlen, cyclop, dupl
func (a AutoAuthenticator) ACL(
	accessType acl.AccessType,
	tokenString string,
	topic string,
) (bool, error) {
	if !a.ValidateAccessType(accessType) {
		return false, ErrInvalidAccessType
	}

	var claims jwt.MapClaims

	if _, _, err := a.Parser.ParseUnverified(tokenString, &claims); err != nil {
		return false, ErrInvalidClaims
	}

	if claims[a.JWTConfig.IssName] == nil {
		return false, ErrIssNotFound
	}

	issuer := fmt.Sprintf("%v", claims[a.JWTConfig.IssName])

	if claims[a.JWTConfig.SubName] == nil {
		return false, ErrSubNotFound
	}

	sub, _ := claims[a.JWTConfig.SubName].(string)

	topicTemplate := a.TopicManager.ParseTopic(topic, issuer, sub, map[string]any(claims))
	if topicTemplate == nil {
		return false, InvalidTopicError{Topic: topic}
	}

	if !topicTemplate.HasAccess(issuer, accessType) {
		return false, TopicNotAllowedError{
			issuer,
			sub,
			accessType,
			topic,
			topicTemplate.Type,
		}
	}

	return true, nil
}

func (a AutoAuthenticator) ValidateAccessType(accessType acl.AccessType) bool {
	for _, allowedAccessType := range a.AllowedAccessTypes {
		if allowedAccessType == accessType {
			return true
		}
	}

	return false
}

func (a AutoAuthenticator) GetCompany() string {
	return a.Company
}

func (a AutoAuthenticator) IsSuperuser() bool {
	return false
}

type autoBlackListChecker struct {
	users map[int]struct{}
	iss   int
}

func newAutoBlackListChecker(cfg config.BlackListUserLogging) autoBlackListChecker {
	users := make(map[int]struct{})
	for _, userID := range cfg.UserIDs {
		users[userID] = struct{}{}
	}

	return autoBlackListChecker{
		users: users,
		iss:   cfg.Iss,
	}
}

func (a autoBlackListChecker) isBlackList(userID, iss int) bool {
	if iss != a.iss {
		return false
	}

	_, ok := a.users[userID]

	return ok
}
