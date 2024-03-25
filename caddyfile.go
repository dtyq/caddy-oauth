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
	"fmt"
	"net/url"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	httpcaddyfile.RegisterDirective("oidc", parseCaddyfile)
}

type oidcConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ClientURL    string `json:"client_url"`
	Scope        string `json:"scope,omitempty"`

	MetadataURL string `json:"metadata_url,omitempty"`
	// use metadata_url or the following fields
	AuthURL       string `json:"auth_url,omitempty"`  // required
	TokenURL      string `json:"token_url,omitempty"` // required
	Issuer        string `json:"issuer,omitempty"`    // required
	UserinfoURL   string `json:"userinfo_url,omitempty"`
	EndSessionURL string `json:"end_session_url,omitempty"`

	clientURL               *url.URL
	clientRedirectURL       *url.URL
	clientCallbackURLString string
	clientLogoutURLString   string
}

func (cfg *oidcConfig) GetClientURL() (url.URL, error) {
	if cfg.clientURL != nil {
		return *cfg.clientURL, nil
	}
	if cfg.ClientURL == "" {
		return url.URL{}, fmt.Errorf("redirect_url is not set")
	}

	repl := caddy.NewReplacer()
	cfg.ClientURL = repl.ReplaceKnown(cfg.ClientURL, "")
	clientURL, err := url.Parse(cfg.ClientURL)
	if err != nil {
		return url.URL{}, fmt.Errorf("failed to parse redirect_url: %w", err)
	}
	cfg.clientURL = clientURL

	return *cfg.clientURL, nil
}

func (cfg *oidcConfig) GetClientRedirectURL() (url.URL, error) {
	if cfg.clientRedirectURL != nil {
		return *cfg.clientRedirectURL, nil
	}

	clientURL, err := cfg.GetClientURL()
	if err != nil {
		return url.URL{}, err
	}

	clientRedirectURL := clientURL
	clientRedirectURL.Path = clientRedirectURL.Path + "/redirect"

	cfg.clientRedirectURL = &clientRedirectURL

	return *cfg.clientRedirectURL, nil
}

func (cfg *oidcConfig) GetClientCallbackURLString() (string, error) {
	if cfg.clientCallbackURLString != "" {
		return cfg.clientCallbackURLString, nil
	}

	clientURL, err := cfg.GetClientURL()
	if err != nil {
		return "", err
	}

	clientCallbackURL := clientURL
	clientCallbackURL.Path = clientCallbackURL.Path + "/callback"

	cfg.clientCallbackURLString = clientCallbackURL.String()

	return cfg.clientCallbackURLString, nil
}

func (cfg *oidcConfig) GetClientLogoutURLString() (string, error) {
	if cfg.clientLogoutURLString != "" {
		return cfg.clientLogoutURLString, nil
	}

	clientURL, err := cfg.GetClientURL()
	if err != nil {
		return "", err
	}

	clientLogoutURL := clientURL
	clientLogoutURL.Path = clientLogoutURL.Path + "/logout"

	cfg.clientLogoutURLString = clientLogoutURL.String()

	return cfg.clientLogoutURLString, nil
}

//	oidc [<matcher>] {
//	    client_id <client_id>
//	    client_secret <client_secret>
//	    redirect_url <redirect_url>
//		[scope <scope>]
//
//		metadata_url <metadata_url>
//		# or
//		auth_url <auth_url>
//		token_url <token_url>
//		issuer <issuer>
//		[userinfo_url <userinfo_url>]
//		[end_session_url <end_session_url>]
//	}
func parseCaddyfileConfig(h httpcaddyfile.Helper) (cfg oidcConfig, err error) {

	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "client_id":
				if !h.Args(&cfg.ClientID) {
					return cfg, h.ArgErr()
				}
			case "client_secret":
				if !h.Args(&cfg.ClientSecret) {
					return cfg, h.ArgErr()
				}
			case "client_url":
				if !h.Args(&cfg.ClientURL) {
					return cfg, h.ArgErr()
				}
			case "scope":
				if !h.Args(&cfg.Scope) {
					return cfg, h.ArgErr()
				}
			case "metadata_url":
				if !h.Args(&cfg.MetadataURL) {
					return cfg, h.ArgErr()
				}
			case "auth_url":
				if !h.Args(&cfg.AuthURL) {
					return cfg, h.ArgErr()
				}
			case "token_url":
				if !h.Args(&cfg.TokenURL) {
					return cfg, h.ArgErr()
				}
			case "issuer":
				if !h.Args(&cfg.Issuer) {
					return cfg, h.ArgErr()
				}
			case "userinfo_url":
				if !h.Args(&cfg.UserinfoURL) {
					return cfg, h.ArgErr()
				}
			case "end_session_url":
				if !h.Args(&cfg.EndSessionURL) {
					return cfg, h.ArgErr()
				}
			default:
				return cfg, h.Errf("unrecognized subdirective: %s", h.Val())
			}
		}
	}

	return
}
func parseCaddyfile(h httpcaddyfile.Helper) (ret []httpcaddyfile.ConfigValue, err error) {
	cfg, err := parseCaddyfileConfig(h)
	if err != nil {
		return nil, err
	}

	clientURL, err := cfg.GetClientURL()
	if err != nil {
		return nil, err
	}
	path := clientURL.Path

	redirectMatcherSet := caddy.ModuleMap{
		"path": caddyconfig.JSON([]string{
			path + "/redirect",
			path + "/callback",
			path + "/logout",
		}, nil),
		"host": caddyconfig.JSON(caddyhttp.MatchPath{clientURL.Host}, nil),
	}
	// fmt.Printf("x%v\n", []string{
	// 	path + "/redirect",
	// 	path + "/callback",
	// 	path + "/logout",
	// })

	r := h.NewRoute(redirectMatcherSet, OIDCAuth{
		oidcConfig: cfg,
		modID:      "http.handlers.oidc_client",
	})
	ret = append(ret, r...)
	// fmt.Printf("xx%v\n", r)

	r = h.NewRoute(caddy.ModuleMap{}, caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"oidc": caddyconfig.JSON(cfg, nil),
		},
	})
	ret = append(ret, r...)

	// fmt.Printf("%v\n", ret)
	return
}
