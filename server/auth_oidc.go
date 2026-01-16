package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/id"
	"golang.org/x/oauth2"
)

var (
	oidcProvider *oidc.Provider
	oauth2Config oauth2.Config
)

func initOIDC() error {
	if !conf.Server.OIDC.Enabled {
		return nil
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, conf.Server.OIDC.Issuer)
	if err != nil {
		return err
	}
	oidcProvider = provider

	oauth2Config = oauth2.Config{
		ClientID:     conf.Server.OIDC.ClientID,
		ClientSecret: conf.Server.OIDC.ClientSecret,
		RedirectURL:  conf.Server.OIDC.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	if conf.Server.OIDC.Scope != "" {
		oauth2Config.Scopes = append([]string{oidc.ScopeOpenID}, conf.Server.OIDC.Scope) // simple split might be needed if multiple scopes in string
	}

	log.Info("OIDC initialized", "issuer", conf.Server.OIDC.Issuer)
	return nil
}

func loginOIDC(w http.ResponseWriter, r *http.Request) {
	if !conf.Server.OIDC.Enabled {
		http.Error(w, "OIDC not enabled", http.StatusNotFound)
		return
	}

	state := generateStateOauth()
	// In a real app, store state in a cookie to verify in callback to prevent CSRF
	setCookie(w, "oauth_state", state, 300)

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func callbackOIDC(ds model.DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !conf.Server.OIDC.Enabled {
			http.Error(w, "OIDC not enabled", http.StatusNotFound)
			return
		}

		// Verify state (CSRF protection)
		stateCookie, err := r.Cookie("oauth_state")
		if err != nil {
			http.Error(w, "State cookie not found", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != stateCookie.Value {
			http.Error(w, "State did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			log.Error(r, "Failed to exchange token", err)
			http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
			return
		}

		userInfo, err := oidcProvider.UserInfo(r.Context(), oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			log.Error(r, "Failed to get userinfo", err)
			http.Error(w, "Failed to get userinfo", http.StatusInternalServerError)
			return
		}

		// Claims
		var claims struct {
			Email             string `json:"email"`
			Verified          bool   `json:"email_verified"`
			PreferredUsername string `json:"preferred_username"`
			Name              string `json:"name"`
		}
		if err := userInfo.Claims(&claims); err != nil {
			log.Error(r, "Failed to parse claims", err)
			http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
			return
		}

		username := claims.PreferredUsername
		if username == "" {
			username = claims.Email
		}
		if username == "" {
			http.Error(w, "No username found in claims", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		user, err := ds.User(ctx).FindByUsername(username)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				if conf.Server.OIDC.UserCreation {
					// Create user
					log.Info(ctx, "Creating new OIDC user", "username", username)
					newUser := model.User{
						ID:          id.NewRandom(),
						UserName:    username,
						Name:        claims.Name,
						Email:       claims.Email,
						IsAdmin:     false,        // Default to non-admin
						LastLoginAt: &time.Time{}, // Will be updated
					}
					// Check if it's the first user? Reuse existing logic?
					c, _ := ds.User(ctx).CountAll()
					if c == 0 {
						newUser.IsAdmin = true
					}

					if err := ds.User(ctx).Put(&newUser); err != nil {
						log.Error(ctx, "Failed to create user", "err", err)
						http.Error(w, "Failed to create user", http.StatusInternalServerError)
						return
					}
					user = &newUser
				} else {
					log.Warn(ctx, "OIDC user not found and creation disabled", "username", username)
					http.Error(w, "User not found", http.StatusForbidden)
					return
				}
			} else {
				log.Error(ctx, "Error finding user", "err", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
		}

		// Generate Navidrome Token
		tokenString, err := auth.CreateToken(user)
		if err != nil {
			log.Error(ctx, "Failed to create token", err)
			http.Error(w, "Failed to create token", http.StatusInternalServerError)
			return
		}

		// Redirect to UI with token
		// Option 1: Cookie. Option 2: Query param.
		// UI expects token in response for login, but this is a redirect flow.
		// Most SPA OIDC flows redirect back to a callback URL in the SPA, but here we are handling callback in backend.
		// We can set a cookie or redirect to /#/login?token=...
		// Let's redirect to root with a temporary cookie or query param.

		// For simplicity and security, we can set the expected headers/cookies if possible,
		// but Navidrome UI uses LocalStorage or SessionStorage usually?
		// Checking Login.jsx... it calls `login` provider.

		// Let's redirect to the main page with `?token=...` handling in the UI (we will need to add that).
		http.Redirect(w, r, conf.Server.BasePath+"/app/#/login?token="+tokenString+"&username="+user.UserName, http.StatusFound)
	}
}

func generateStateOauth() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(ttl * time.Second),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
}
