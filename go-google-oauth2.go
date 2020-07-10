/*
???
*/
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var googleOauthConfig *oauth2.Config

var (
	Priority int    = 1005
	Version  string = "1.1.1"
)

const (
	oauthGoogleUserInfoURL string = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
)

// Config contains the schema defined for the Kong Admin API to populate data
// https://docs.konghq.com/2.0.x/go/#configuration-structure
type Config struct {
	HostedDomains       []string `json:"hosted_domains"`
	HmacSecret          string   `json:"hmac_secret"`
	ClientID            string   `json:"client_id"`
	ClientSecret        string   `json:"client_secret"`
	RedirectURLOverride string   `json:"redirect_url_override"`
	ConsumerLookup      string   `json:"consumer_lookup"`
}

// User is the response object from the Google User Info API
type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
	HostedDomain  string `json:"hd"`
}

// New ensures that Kong knows what your configuration is
// https://docs.konghq.com/2.0.x/go/#new-constructor
func New() interface{} {
	return &Config{}
}

// Access is executed for every request from a client and before it is being proxied to the upstream service.
// HTTP/HTTPS requests
func (conf Config) Access(kong *pdk.PDK) {
	kong.Log.Info(fmt.Sprintf("%v", conf))

	redirectFullHost := conf.RedirectURLOverride
	if redirectFullHost == "" {
		scheme, _ := kong.Request.GetForwardedScheme()
		host, _ := kong.Request.GetForwardedHost()
		port, _ := kong.Request.GetForwardedPort()

		redirectFullHost = fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}

	googleOauthConfig = &oauth2.Config{
		RedirectURL:  fmt.Sprintf("%s/oauth/callback", redirectFullHost),
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	responseHeaders := make(map[string][]string)
	path, err := kong.Request.GetPath()
	if err != nil {
		kong.Log.Err(err.Error())
		kong.Response.Exit(500, "internal server error", responseHeaders)
	}

	switch path {
	case "/oauth/login":
		err := oauthLogin(kong)
		if err != nil {
			handleHTTPError(kong, err, responseHeaders)
		}
		return
	case "/oauth/logout":
		clearOauthCookie := http.Cookie{Name: "kong-oauth", Value: "", Expires: time.Now().Add(-1 * time.Hour), Path: "/"}

		err = kong.Response.SetHeader("Set-Cookie", clearOauthCookie.String())
		if err != nil {
			handleHTTPError(kong, err, responseHeaders)
		}

		redirect(kong, 302, "/oauth/login")
		return
	case "/oauth/callback":
		err := oauthCallback(kong, []byte(conf.HmacSecret))
		if err != nil {
			handleHTTPError(kong, err, responseHeaders)
		}

		redirect(kong, 302, "/")
		return
	}

	kong.Log.Info("get oauth jwt")
	cookieKongOauth, err := kong.Nginx.GetVar("cookie_kong-oauth")
	if err != nil {
		return
	}

	kong.Log.Info("parse jwt")
	token, err := jwt.Parse(cookieKongOauth, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New(fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"]))
		}

		return []byte(conf.HmacSecret), nil
	})

	kong.Log.Info("validate jwt")
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if len(conf.HostedDomains) > 0 {
			kong.Log.Info("checking hosted domain")

			trusted := false
			for _, hostedDomain := range conf.HostedDomains {
				if hostedDomain == claims["hd"] {
					trusted = true
				}
			}

			if !trusted {
				return
			}
		}
	} else {
		kong.Log.Info("token invalid or not OK")
		return
	}

	consumer, _ := kong.Client.LoadConsumer(conf.ConsumerLookup, true)

	// Everything is grand
	kong.Client.Authenticate(&consumer, nil)
}

func oauthLogin(kong *pdk.PDK) error {
	kong.Log.Info("oauthLogin")

	oauthState, cookieString := generateStateOauthCookie()
	kong.Log.Info("cookieString ", cookieString)

	err := kong.Response.SetHeader("Set-Cookie", cookieString)
	if err != nil {
		return err
	}

	authCodeURL := googleOauthConfig.AuthCodeURL(oauthState)
	kong.Log.Info("authCodeURL ", authCodeURL)

	redirect(kong, 302, authCodeURL)
	return nil
}

func oauthCallback(kong *pdk.PDK, hmacSuperSecret []byte) error {
	kong.Log.Info("oauthCallback")

	cookieOauthState, err := kong.Nginx.GetVar("cookie_oauthstate")
	if err != nil {
		return err
	}
	kong.Log.Info("cookieOauthState ", cookieOauthState)

	callbackOauthState, err := kong.Request.GetQueryArg("state")
	if err != nil {
		return err
	}
	kong.Log.Info("callbackOauthState ", callbackOauthState)

	if cookieOauthState != callbackOauthState {
		kong.Log.Err("oauth state mismatch")
		return ErrAccessDenied
	}

	code, err := kong.Request.GetQueryArg("code")
	if err != nil {
		return err
	}
	kong.Log.Info("code ", code)

	userResponse, err := getUserDataFromGoogle(code)
	if err != nil {
		return err
	}

	var user User
	err = json.Unmarshal(userResponse, &user)
	if err != nil {
		return err
	}

	expiryTime := time.Now().Add(24 * time.Hour)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.Email,
		"hd":  user.HostedDomain,
		"iat": time.Now().Unix(),
		"exp": expiryTime.Unix(),
		"nbf": time.Date(2020, 0, 0, 0, 0, 0, 0, time.UTC).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(hmacSuperSecret)
	if err != nil {
		return err
	}

	kong.Log.Info(tokenString)
	jwtCookie := http.Cookie{Name: "kong-oauth", Value: tokenString, Expires: expiryTime, Path: "/"}

	err = kong.Response.SetHeader("Set-Cookie", jwtCookie.String())
	if err != nil {
		return err
	}

	return nil
}

func generateStateOauthCookie() (string, string) {
	var expiration = time.Now().Add(15 * time.Minute)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration, Path: "/"}

	return state, cookie.String()
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	// Use code to get token and get user info from Google.

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}
	response, err := http.Get(oauthGoogleUserInfoURL + token.AccessToken)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return contents, nil
}

// Helper function for HTTP erroring
func handleHTTPError(kong *pdk.PDK, err error, responseHeaders map[string][]string) {
	switch err {
	case ErrAccessDenied:
		kong.Response.Exit(403, "access denied", responseHeaders)
	default:
		kong.Log.Err(err.Error())
		kong.Response.Exit(500, "internal server error", responseHeaders)
	}
}

// Helper function for redirecting
func redirect(kong *pdk.PDK, statusCode int, url string) {
	kong.Response.Exit(statusCode, "", map[string][]string{
		"Location": []string{
			url,
		},
	})
}

var (
	ErrAccessDenied = errors.New("access denied")
)
