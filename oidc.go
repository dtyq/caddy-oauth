// Copyright 2024 KK Group
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/markbates/goth/providers/openidConnect"
	"go.uber.org/zap"
)

func init() {
	// caddy.RegisterModule(OIDCAuth{})
	caddy.RegisterModule(OIDCAuth{modID: "http.authentication.providers.oidc"})
	caddy.RegisterModule(OIDCAuth{modID: "http.handlers.oidc_client"})
}

type User = caddyauth.User

const redirectHTML = `
<!DOCTYPE html>
<html>
<head>
<meta content="text/html;charset=utf-8" http-equiv="Content-Type">
<meta content="utf-8" http-equiv="encoding">
<meta http-equiv="refresh" content="0;url=%s">
<meta name="referrer" content="no-referrer">
<title>Redirecting...</title>
</head>
<body>
<p>You are being redirected to <a href="%s">%s</a></p>
</body>
</html>
`

type OIDCAuth struct {
	oidcConfig
	caddyhttp.MiddlewareHandler `json:"-"`

	logger   *zap.Logger
	provider *openidConnect.Provider
	jwks     jwk.Set

	// a little hacky: mod id changes
	modID string
}

func (o OIDCAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		// ID:"http.authentication.providers.oidc",
		// New: func() caddy.Module {
		// 	return new(OIDCAuth)
		// },
		ID: caddy.ModuleID(o.modID),
		New: func() caddy.Module {
			ret := new(OIDCAuth)
			ret.modID = o.modID
			return ret
		},
	}
}

func (o *OIDCAuth) Provision(ctx caddy.Context) (err error) {
	o.logger = ctx.Logger(o)
	repl := caddy.NewReplacer()

	o.Scope = repl.ReplaceKnown(o.Scope, "")
	if o.Scope == "" {
		o.Scope = "openid"
	}

	if err := o.probeMetadata(); err != nil {
		return fmt.Errorf("failed to probe metadata: %w", err)
	}

	callbackURLString, err := o.GetClientCallbackURLString()
	if err != nil {
		return fmt.Errorf("failed to get callback url: %w", err)
	}

	o.provider, err = openidConnect.NewCustomisedURL(
		repl.ReplaceKnown(o.ClientID, ""),
		repl.ReplaceKnown(o.ClientSecret, ""),
		callbackURLString,
		repl.ReplaceKnown(o.AuthURL, ""),
		repl.ReplaceKnown(o.TokenURL, ""),
		repl.ReplaceKnown(o.Issuer, ""),
		repl.ReplaceKnown(o.UserinfoURL, ""),
		repl.ReplaceKnown(o.EndSessionURL, ""),
		strings.Split(o.Scope, " ")...,
	)
	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	return
}

func (o *OIDCAuth) Error(err error) {
	o.logger.Error("error", zap.Error(err))
}

func (o *OIDCAuth) probeMetadata() (err error) {
	repl := caddy.NewReplacer()
	metadataURL := repl.ReplaceKnown(o.MetadataURL, "")

	request, err := http.NewRequest(http.MethodGet, metadataURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	var metadata map[string]interface{}

	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	var ok bool
	if o.AuthURL == "" {
		o.AuthURL, ok = metadata["authorization_endpoint"].(string)
		if !ok {
			return fmt.Errorf("missing authorization_endpoint")
		}
	}

	if o.TokenURL == "" {
		o.TokenURL, ok = metadata["token_endpoint"].(string)
		if !ok {
			return fmt.Errorf("missing token_endpoint")
		}
	}

	if o.Issuer == "" {
		o.Issuer, ok = metadata["issuer"].(string)
		if !ok {
			return fmt.Errorf("missing issuer")
		}
	}

	if o.UserinfoURL == "" {
		o.UserinfoURL, _ = metadata["userinfo_endpoint"].(string)
	}

	if o.EndSessionURL == "" {
		o.EndSessionURL, _ = metadata["end_session_endpoint"].(string)
	}

	jwksEndpoint, ok := metadata["jwks_uri"].(string)
	if !ok {
		return fmt.Errorf("missing jwks_uri")
	}

	request, err = http.NewRequest(http.MethodGet, jwksEndpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	response, err = http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	jwks := jwk.NewSet()

	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	o.jwks = jwks

	return nil
}

func (o *OIDCAuth) Validate() error {
	if o.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if o.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	if o.ClientURL == "" {
		return fmt.Errorf("client_url is required")
	}
	if o.MetadataURL == "" && (o.AuthURL == "" || o.TokenURL == "" || o.Issuer == "") {
		return fmt.Errorf("metadata_url is required")
	}
	return nil
}

func (o *OIDCAuth) Authenticate(w http.ResponseWriter, r *http.Request) (User, bool, error) {
	// fmt.Printf("%v, %v\n", r.URL, o.clientURL)
	var err error
	var user User
	var t jwt.Token
	var claimMap map[string]interface{}
	var stdClaimMap map[string]string
	var logoutURLString string
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	jsonString := func(v interface{}) string {
		b, _ := json.Marshal(v)
		return string(b)
	}

	cookie := getCookie(r, "caddy_id_token")
	if cookie == "" {
		goto noCookie
	}

	// fmt.Printf("cookie: %v\n", cookie)

	// validate id token
	t, err = jwt.Parse(
		[]byte(cookie),
		jwt.WithKeySet(o.jwks),
	)
	if err != nil {
		goto noCookie
	}

	err = jwt.Validate(
		t,
		jwt.WithIssuer(o.Issuer),
	)
	if err != nil {
		goto noCookie
	}

	// // flatten claims
	// for k, v := range t.PrivateClaims() {
	// 	claimMap[k] = v
	// }

	user.ID = t.Subject()
	user.Metadata = make(map[string]string)
	claimMap, err = t.AsMap(context.Background())
	if err == nil {
		for k, v := range claimMap {
			if v == nil || v == "" {
				// skip it
				continue
			}
			// fmt.Printf("%v: %v\n", k, v)
			if sv, ok := v.(string); ok {
				user.Metadata[k] = sv
			} else {
				user.Metadata[k] = jsonString(v)
			}
		}
	}
	stdClaimMap = map[string]string{
		"aud": jsonString(t.Audience()),
		"exp": t.Expiration().Format("2006-01-02T15:04:05Z07:00"),
		"iat": t.IssuedAt().Format("2006-01-02T15:04:05Z07:00"),
		"iss": t.Issuer(),
		"jti": t.JwtID(),
		"nbf": t.NotBefore().Format("2006-01-02T15:04:05Z07:00"),
		"sub": t.Subject(),
	}
	for k, v := range stdClaimMap {
		if v == "" {
			// skip it
			continue
		}
		user.Metadata[k] = v
	}

	// fmt.Printf("user: %v\n", jsonString(user))
	logoutURLString, err = o.GetClientLogoutURLString()
	if err != nil {
		return user, false, err
	}
	repl.Set("oauth.logout_url", logoutURLString)
	return user, true, nil

noCookie:
	returnURL := r.URL
	returnURL.Host = r.Host
	redirectURL, err := o.oidcConfig.GetClientRedirectURL()
	if err != nil {
		return user, false, err
	}
	query := redirectURL.Query()
	query["return_url"] = []string{returnURL.String()}
	redirectURL.RawQuery = query.Encode()
	if err != nil {
		return user, false, err
	}
	repl.Set("oauth.redirect_url", redirectURL.String())
	return user, false, nil
}

func (o OIDCAuth) handleRedirect(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	state := r.URL.Query().Get("return_url")
	state = url.QueryEscape(state)

	sess, err := o.provider.BeginAuth(state)
	if err != nil {
		o.logger.Error("failed to begin auth", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	authURL, err := sess.GetAuthURL()
	if err != nil {
		o.logger.Error("failed to get auth url", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	// fmt.Printf("%v\n", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

func setCookie(w http.ResponseWriter, r *http.Request, name string, value string, expires time.Time) {
	valBytes := []byte(value)
	count := 0
	secure := false
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		secure = true
	}
	for i := 0; i < len(valBytes); i += 2048 {
		cookie := http.Cookie{
			Name:     fmt.Sprintf("%s.%d", name, count),
			Value:    string(valBytes[i:min(i+2048, len(valBytes))]),
			Expires:  expires,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   secure,
		}
		http.SetCookie(w, &cookie)
		count++
	}
}

func getCookie(r *http.Request, name string) (value string) {
	needle := fmt.Sprintf("%s.", name)
	parts := make(map[int]string)
	count := 0
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, needle) {
			continue
		}
		indexStr := strings.TrimPrefix(cookie.Name, needle)
		index, err := strconv.Atoi(indexStr)
		if err != nil {
			continue
		}
		parts[index] = cookie.Value
		count = max(index, count)
		// fmt.Printf("cookie: %v %v %v\n", index, cookie.Name, cookie.Value)
	}

	for i := 0; i <= count; i++ {
		s, ok := parts[i]
		if !ok {
			return ""
		}
		value += s
	}
	// fmt.Printf("cookie: %v\n", value)
	return
}

func (o OIDCAuth) handleCallback(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	query := r.URL.Query()

	// on callback
	state := query.Get("state")
	returnURL, err := url.Parse(state)
	if err != nil {
		o.logger.Error("failed to parse state", zap.Error(err))
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	sess := openidConnect.Session{}
	_, err = sess.Authorize(o.provider, query)
	if err != nil {
		o.logger.Error("failed to authorize", zap.Error(err))
		return caddyhttp.Error(http.StatusForbidden, err)
	}

	// fmt.Printf("sess: %v, %v\n", sess, returnURL)

	// validate id token
	t, err := jwt.Parse(
		[]byte(sess.IDToken),
		jwt.WithKeySet(o.jwks),
	)
	if err != nil {
		o.logger.Error("cannot parse id token", zap.Error(err))
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	err = jwt.Validate(
		t,
		jwt.WithIssuer(o.Issuer),
	)
	if err != nil {
		o.logger.Error("cannot validate id token", zap.Error(err))
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	setCookie(w, r, "caddy_id_token", sess.IDToken, t.Expiration())
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	// TODO: go tmpl
	page := fmt.Sprintf(redirectHTML, returnURL.String(), returnURL.String(), returnURL.String())
	w.Header().Add("Content-Length", fmt.Sprintf("%d", len(page)))
	w.Header().Add("Cache-Control", "no-store")
	w.Write([]byte(page))
	w.WriteHeader(http.StatusOK)
	return nil
}

func (o OIDCAuth) handleLogout(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	setCookie(w, r, "caddy_id_token", "invalid", time.Now().Add(-time.Hour))
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	// TODO: go tmpl
	page := fmt.Sprintf(redirectHTML, "/", "/", "/")
	w.Header().Add("Content-Length", fmt.Sprintf("%d", len(page)))
	w.Header().Add("Cache-Control", "no-store")
	w.Write([]byte(page))
	w.WriteHeader(http.StatusOK)
	return nil
}

func (o OIDCAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// fmt.Printf("%v, %v\n", r.URL, o.RedirectURL)
	clientURL, err := o.GetClientURL()
	if err != nil {
		// impossible
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	// fmt.Printf("r: %v p: %v\n", r.URL.Path, clientURL.Path)
	subPath := strings.TrimPrefix(r.URL.Path, clientURL.Path)
	// fmt.Printf("subPath: %v\n", subPath)
	switch subPath {
	case "/redirect":
		return o.handleRedirect(w, r, next)
	case "/callback":
		return o.handleCallback(w, r, next)
	case "/logout":
		return o.handleLogout(w, r, next)
	}
	return caddyhttp.Error(http.StatusNotFound, nil)
}
