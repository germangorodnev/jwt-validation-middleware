package multi_jwt_validation_middleware

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type JWTConfig struct {
	Secret         string            `json:"secret,omitempty"`
	Optional       bool              `json:"optional,omitempty"`
	PayloadHeaders map[string]string `json:"payloadHeaders,omitempty"`
	AuthQueryParam string            `json:"authQueryParam,omitempty"`
	AuthCookieName string            `json:"authCookieName,omitempty"`
	ForwardAuth    bool              `json:"forwardAuth,omitempty"`
}

// Main middleware config
type Config struct {
	Configs []*JWTConfig `json:"configs,omitempty"`
}

func CreateParameters() *JWTConfig {
	return &JWTConfig{
		Secret:         "SECRET",
		Optional:       false,
		AuthQueryParam: "authToken",
		AuthCookieName: "authToken",
		ForwardAuth:    false,
	}
}

func CreateConfig() *Config {
	return &Config{
		Configs: []*JWTConfig{CreateParameters()},
	}
}

type JWT struct {
	next    http.Handler
	name    string
	configs []*JWTConfig
}

type Token struct {
	plaintext []byte
	payload   map[string]interface{}
	signature []byte
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &JWT{
		next:    next,
		name:    name,
		configs: config.Configs,
	}, nil
}

func (j *JWT) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	var lastError error
	var lastStatus int
	for _, config := range j.configs {
		token, err := j.ExtractToken(request, config)
		if token == nil {
			if err != nil {
				lastError = err
				lastStatus = http.StatusInternalServerError
				continue
			}
			if !config.Optional {
				lastError = fmt.Errorf("no token provided")
				lastStatus = http.StatusUnauthorized
				continue
			}
			j.next.ServeHTTP(response, request)
			return
		}

		verified, err := j.VerifyTokenSignature(token, config.Secret)
		if err != nil {
			lastError = err
			lastStatus = http.StatusInternalServerError
			continue
		}

		if !verified {
			lastError = fmt.Errorf("invalid token signature")
			lastStatus = http.StatusUnauthorized
			continue
		}

		// Validate expiration, when provided and signature is valid
		if exp, ok := token.payload["exp"]; ok {
			if expInt, err := strconv.ParseInt(fmt.Sprint(exp), 10, 64); err != nil || expInt < time.Now().Unix() {
				lastError = fmt.Errorf("token is expired")
				lastStatus = http.StatusUnauthorized
				continue
			}
		}

		// Inject header as proxypayload or configured name
		for k, v := range config.PayloadHeaders {
			if payloadValue, ok := token.payload[v]; ok {
				request.Header.Add(k, fmt.Sprint(payloadValue))
			}
		}

		j.next.ServeHTTP(response, request)
		return
	}

	// no suitable config
	if lastError != nil {
		http.Error(response, lastError.Error(), lastStatus)
	} else {
		http.Error(response, "no valid token found", http.StatusUnauthorized)
	}
}

func (j *JWT) VerifyTokenSignature(token *Token, secret string) (bool, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(token.plaintext)
	expectedMAC := mac.Sum(nil)

	return hmac.Equal(token.signature, expectedMAC), nil
}

func (j *JWT) ExtractToken(req *http.Request, config *JWTConfig) (*Token, error) {
	rawToken := j.extractTokenFromHeader(req, config)
	if len(rawToken) == 0 && config.AuthQueryParam != "" {
		rawToken = j.extractTokenFromQuery(req, config)
	}
	if len(rawToken) == 0 && config.AuthCookieName != "" {
		rawToken = j.extractTokenFromCookie(req, config)
	}
	if len(rawToken) == 0 {
		return nil, nil
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	token := Token{
		plaintext: []byte(rawToken[0 : len(parts[0])+len(parts[1])+1]),
		signature: signature,
	}
	d := json.NewDecoder(bytes.NewBuffer(payload))
	d.UseNumber()
	err = d.Decode(&token.payload)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (j *JWT) extractTokenFromCookie(request *http.Request, config *JWTConfig) string {
	cookie, err := request.Cookie(config.AuthCookieName)
	if err != nil {
		return ""
	}
	if !config.ForwardAuth {
		cookies := request.Cookies()
		request.Header.Del("Cookie")
		for _, c := range cookies {
			if c.Name != config.AuthCookieName {
				request.AddCookie(c)
			}
		}
	}
	return cookie.Value
}

func (j *JWT) extractTokenFromQuery(request *http.Request, config *JWTConfig) string {
	if request.URL.Query().Has(config.AuthQueryParam) {
		token := request.URL.Query().Get(config.AuthQueryParam)
		if !config.ForwardAuth {
			qry := request.URL.Query()
			qry.Del(config.AuthQueryParam)
			request.URL.RawQuery = qry.Encode()
			request.RequestURI = request.URL.RequestURI()
		}
		return token
	}
	return ""
}

func (j *JWT) extractTokenFromHeader(request *http.Request, config *JWTConfig) string {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		return ""
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}

	if !config.ForwardAuth {
		request.Header.Del("Authorization")
	}
	return auth[7:]
}
