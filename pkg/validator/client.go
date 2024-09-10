package validator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	ServiceNameHeader = "X-Service-Name"

	validateURI    = "/api/v3/internal/validate"
	authHeader     = "Authorization"
	userDataHeader = "X-User-Data"
	modeQueryParam = "mode"
)

var (
	ErrEmptyServiceName      = errors.New("x-service-name can not be empty")
	ErrInvalidJWT            = errors.New("invalid jwt")
	ErrInvalidUserDataHeader = errors.New("invalid X-User-Data header")
	ErrRequestFailed         = errors.New("validator request failed")
)

type Client struct {
	baseURL    string
	client     *http.Client
	timeout    time.Duration
	isOptional bool
}

type Payload struct {
	IAT    int    `json:"iat"`
	Aud    string `json:"aud"`
	Iss    int    `json:"iss"`
	Sub    string `json:"sub"`
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	Exp    int    `json:"exp"`
	Locale string `json:"locale"`
	Sid    string `json:"sid"`
}

// New creates a new Client with default attributes.
func New(url string, timeout time.Duration) Client {
	return Client{
		baseURL:    url,
		client:     new(http.Client),
		timeout:    timeout,
		isOptional: false,
	}
}

// WithOptionalValidate enables you to bypass the signature validation.
// If the validation of the JWT signature is optional for you, and you just want to extract
// the payload from the token, you can use the client in `WithOptionalValidate` mode.
func (c *Client) WithOptionalValidate() {
	c.isOptional = true
}

// Validate gets the parent context, headers, and JWT token and calls the validate API of the JWT validator service.
// The parent context is helpful in canceling the process in the upper hand (a function that used the SDK) and in case
// you have something like tracing spans in your context and want to extend these things in your custom HTTP handler.
// Otherwise, you can use `context.Background()`.
// The headers argument is used when you want to pass some headers like user-agent,
// X-Service-Name, X-App-Name, X-App-Version and
// X-App-Version-Code to the validator. It is extremely recommended to pass these headers (if you have them) because
// it increases the visibility in the logs and metrics of the JWT Validator service.
// You must place your Authorization header content in the bearerToken argument.
// Consider that the bearerToken must contain Bearer keyword and JWT.
// For `X-Service-Name` you should put your project/service name in this header.
// nolint: funlen, cyclop
func (c *Client) Validate(parentCtx context.Context, headers http.Header, bearerToken string) (*Payload, error) {
	if headers.Get(ServiceNameHeader) == "" {
		return nil, ErrEmptyServiceName
	}

	segments := strings.Split(bearerToken, " ")
	if len(segments) < 2 || strings.ToLower(segments[0]) != "bearer" {
		return nil, ErrInvalidJWT
	}

	ctx, cancel := context.WithTimeout(parentCtx, c.timeout)
	defer cancel()

	url := c.baseURL + validateURI

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("validator creating request failed %w", err)
	}

	request.Header = headers
	request.Header.Set(authHeader, bearerToken)

	query := request.URL.Query()
	if c.isOptional {
		query.Add(modeQueryParam, "optional")
	}

	request.URL.RawQuery = query.Encode()

	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("validator sending request failed %w", err)
	}

	closeBody(response)

	if response.StatusCode != http.StatusOK {
		return nil, ErrRequestFailed
	}

	userDataHeader := response.Header.Get(userDataHeader)
	if userDataHeader == "" {
		return nil, ErrInvalidJWT
	}

	userData := map[string]interface{}{}

	if err := json.Unmarshal([]byte(userDataHeader), &userData); err != nil {
		return nil, fmt.Errorf("X-User-Data header unmarshal failed: %w", err)
	}

	payload := new(Payload)
	if iat, ok := userData["iat"].(float64); ok {
		payload.IAT = int(iat)
	}

	if aud, ok := userData["aud"].(string); ok {
		payload.Aud = aud
	}

	if iss, ok := userData["iss"].(float64); ok {
		payload.Iss = int(iss)
	}

	if sub, ok := userData["sub"].(string); ok {
		payload.Sub = sub
	}

	if userID, ok := userData["user_id"].(float64); ok {
		payload.UserID = int(userID)
	}

	if email, ok := userData["email"].(string); ok {
		payload.Email = email
	}

	if exp, ok := userData["exp"].(float64); ok {
		payload.Exp = int(exp)
	}

	if locale, ok := userData["locale"].(string); ok {
		payload.Locale = locale
	}

	if sid, ok := userData["sid"].(string); ok {
		payload.Sid = sid
	}

	return payload, nil
}

// closeBody to avoid memory leak when reusing http connection.
func closeBody(response *http.Response) {
	if response != nil {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
}
