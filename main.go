package main

import (
	"context"
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joeshaw/envdecode"
	"github.com/ory/hydra/rand/sequence"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"golang.org/x/oauth2"
)

type Config struct {
	IssuerURL        string   `env:"HYDRA_PUBLIC_URL,default=http://blockbook-dev.corp:4444/"`
	RevokeLoginURL   string   `env:"REVOKE_LOGIN_URL,default=http://blockbook-dev.corp:4445/oauth2/auth/sessions/login/"`
	RevokeConsentURL string   `env:"REVOKE_CONSENT_URL,default=http://blockbook-dev.corp:4445/oauth2/auth/sessions/consent/"`
	IntrospectURL    string   `env:"INTROSPECT_URL,default=http://blockbook-dev.corp:4445/oauth2/introspect"`
	ResourceProxyURL string   `env:"RESOURCE_PROXY_URL,default=http://blockbook-dev.corp:4455/api/"`
	ListenAddr       string   `env:"LISTEN_ADDR,default=:8080"`
	CallbackURL      string   `env:"CALLBACK_URL,default=http://localhost:8080/callback"`
	Scopes           []string `env:"SCOPES,default=openid;offline;id_token;wallet;demo"`
}

type UserInfo struct {
	LoggedIn bool
	Token    *oauth2.Token
}

type TokenInfo struct {
	Subject string
	Email   string
}

var (
	config       *Config
	oauth2Config *oauth2.Config
	oidcProvider *oidc.Provider
	oidcVerifier *oidc.IDTokenVerifier
)

// Note: Don't store your key in your source code. Pass it via an
// environmental variable, or flag (or both), and don't accidentally commit it
// alongside your code. Ensure your key is sufficiently random - i.e. use Go's
// crypto/rand or securecookie.GenerateRandomKey(32) and persist the result.
var store = sessions.NewCookieStore([]byte("session-key"))

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	gob.Register(&UserInfo{})

	var c Config
	err := envdecode.Decode(&c)
	if err != nil {
		log.Fatalf("Config parsing failed: %s", err)
	}
	config = &c

	withTimeout(500, func(ctx context.Context) {
		oidcProvider, err = oidc.NewProvider(ctx, config.IssuerURL)
	})
	if err != nil {
		log.Fatal(err)
	}

	oauth2Config = &oauth2.Config{
		RedirectURL:  config.CallbackURL,
		ClientID:     "login-demo",
		ClientSecret: "5j34lk6hj",
		Scopes:       config.Scopes,
		Endpoint:     oidcProvider.Endpoint(),
	}

	oidcVerifier = oidcProvider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})
}

func main() {
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/", indexHandler)
	router.HandleFunc("/login", loginHandler)
	router.HandleFunc("/callback", callbackHandler)
	router.HandleFunc("/logout", logoutHandler)
	router.HandleFunc("/introspect/{type:token}", introspectHandler)
	router.HandleFunc("/resource/{path:.*}", resourceHandler)
	router.HandleFunc("/upload", uploadHandler)

	http.ListenAndServeTLS(config.ListenAddr, "cert/server.crt", "cert/server.key", router)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"issuerURL": config.IssuerURL,
	}

	session, _ := store.New(r, "demo-app-session")
	ui := getUserInfo(session)
	var ti *TokenInfo
	if ui != nil {
		if ui.LoggedIn {
			token, err := refreshToken(ui.Token)
			if err != nil {
				log.Print(err)
				ui.LoggedIn = false
				ui.Token = nil
			} else {
				ui.Token = token
			}
		}
		session.Values["user-info"] = ui

		log.Printf("Token: %+v", ui.Token)

		data["isAuthenticated"] = ui.LoggedIn

		var err error
		if ti, err = getOAuth2TokenInfo(ui.Token); err == nil {
			data["subject"] = ti.Subject
			data["email"] = ti.Email
		} else {
			log.Printf("Error introspecting token: %s", err)
		}

		data["objects"] = listObjects(ui.Token, ti, "wallet", "demo")
	}
	session.Save(r, w)

	executeTemplate(w, "templates/index.html", data)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	seq, err := sequence.RuneSequence(24, sequence.AlphaLower)
	if err != nil {
		log.Printf("Could not generate random state: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	state := string(seq)

	loginURL := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	log.Println(loginURL)

	session, _ := store.New(r, "demo-app-session")
	session.Values["state"] = state
	session.Save(r, w)

	http.Redirect(w, r, loginURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	scope := q.Get("scope")
	state := q.Get("state")

	errorCode := q.Get("error")
	if errorCode != "" {
		errorDescription := q.Get("error_description")
		errorHint := q.Get("error_hint")

		log.Printf("Authentication error: %s\n\nDescription: %s\nHint: %s", errorCode, errorDescription, errorHint)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Authentication error: %s\n\nDescription: %s\nHint: %s", errorCode, errorDescription, errorHint)
		return
	}

	session, _ := store.New(r, "demo-app-session")

	var storedState string
	if s, ok := session.Values["state"]; ok {
		if s, ok := s.(string); ok {
			storedState = s
		}
	}

	if state != storedState {
		log.Printf("Invalid state: %q != %q", state, storedState)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid state")
		return
	}

	delete(session.Values, "state")

	var (
		token *oauth2.Token
		err   error
	)
	withTimeout(500, func(ctx context.Context) {
		token, err = oauth2Config.Exchange(ctx, code)
	})
	if err != nil {
		log.Println("OAuth2 exchange:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var rawIDToken string
	if v := token.Extra("id_token"); v != nil {
		if s, ok := v.(string); ok {
			rawIDToken = s
		}
	}
	// var idToken *oidc.IDToken
	// idToken, err = oidcVerifier.Verify(context.Background(), rawIDToken)
	// if err != nil {
	// 	log.Println("Verify id_token:", err)
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	return
	// }

	session.Values["user-info"] = &UserInfo{
		LoggedIn: true,
		Token:    token,
	}

	session.Save(r, w)

	ui, err := getOIDCUserInfo(token)
	if err != nil {
		log.Println("Get user info:", err)
	}

	ti, err := getOAuth2TokenInfo(token)
	if err != nil {
		log.Println("Get token info:", err)
	}

	data := map[string]interface{}{
		"code":       code,
		"scope":      scope,
		"state":      state,
		"token":      token,
		"userInfo":   ui,
		"tokenInfo":  ti,
		"rawIDToken": rawIDToken,
	}

	executeTemplate(w, "templates/callback.html", data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.New(r, "demo-app-session")

	token, err := loadToken(session)
	if err == nil {
		token, err = refreshToken(token)
	}
	if err != nil {
		log.Print(err)
	}

	delete(session.Values, "user-info")
	session.Save(r, w)

	if token != nil {
		ti, err := getOAuth2TokenInfo(token)
		if err != nil {
			log.Print(err)
		} else {
			revokeConsent(token, ti.Subject)
			revokeLogin(token, ti.Subject)
		}
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func loadToken(session *sessions.Session) (token *oauth2.Token, err error) {
	if ui := getUserInfo(session); ui != nil {
		token = ui.Token
	}
	if token == nil {
		err = fmt.Errorf("Cannot load token from session")
	}
	return
}

func refreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	ts := oauth2Config.TokenSource(context.Background(), token)
	ts = oauth2.ReuseTokenSource(token, ts)
	return ts.Token()
}

func storeToken(session *sessions.Session, token *oauth2.Token) {
	if ui := getUserInfo(session); ui != nil {
		ui.Token = token
	} else {
		delete(session.Values, "user-info")
	}
}

func getUserInfo(session *sessions.Session) *UserInfo {
	if ui, ok := session.Values["user-info"]; ok {
		if ui, ok := ui.(*UserInfo); ok {
			return ui
		} else {
			log.Printf("Invalid type of user-info field: %T", ui)
		}
	} else {
		// log.Println("user-info not set")
	}

	return nil
}

func getOIDCUserInfo(token *oauth2.Token) (userInfo *oidc.UserInfo, err error) {
	withTimeout(500, func(ctx context.Context) {
		ts := oauth2Config.TokenSource(ctx, token)
		userInfo, err = oidcProvider.UserInfo(ctx, ts)
	})
	return
}

func getOAuth2TokenInfo(token *oauth2.Token) (*TokenInfo, error) {
	ti, err := introspectOAuth2Token(token)
	if err != nil {
		return nil, err
	}

	var email string
	if e, ok := ti.Ext["email"]; ok {
		if e, ok := e.(string); ok {
			email = e
		}
	}

	return &TokenInfo{
		Subject: ti.Sub,
		Email:   email,
	}, nil
}

func revokeConsent(token *oauth2.Token, subject string) {
	url := config.RevokeConsentURL + subject
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		log.Print(err)
		return
	}
	token.SetAuthHeader(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Print(err)
		return
	}
	if res.StatusCode != http.StatusNoContent {
		log.Printf("Request failed: %s: %s", url, res.Status)
	}
}

func revokeLogin(token *oauth2.Token, subject string) {
	url := config.RevokeLoginURL + subject
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		log.Print(err)
		return
	}
	token.SetAuthHeader(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Print(err)
		return
	}
	if res.StatusCode != http.StatusNoContent {
		log.Printf("Request failed: %s: %s", url, res.Status)
	}
}

func introspectHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.New(r, "demo-app-session")

	token, err := loadToken(session)
	if err == nil {
		token, err = refreshToken(token)
	}
	if err != nil {
		log.Print(err)
		delete(session.Values, "user-info")
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	storeToken(session, token)
	session.Save(r, w)

	ti, err := introspectOAuth2Token(token)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	err = e.Encode(ti)
	if err != nil {
		log.Print(err)
	}
}

func introspectOAuth2Token(token *oauth2.Token) (*swagger.OAuth2TokenIntrospection, error) {
	form := url.Values{}
	form.Set("token", token.AccessToken)
	req, err := http.NewRequest("POST", config.IntrospectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var ti *swagger.OAuth2TokenIntrospection
	d := json.NewDecoder(res.Body)
	err = d.Decode(&ti)
	if err != nil {
		return nil, err
	}

	return ti, nil
}

func withTimeout(ms int, fn func(ctx context.Context)) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ms)*time.Millisecond)
	defer cancel()
	fn(ctx)
}

func resourceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	session, _ := store.New(r, "demo-app-session")

	token, err := loadToken(session)
	if err == nil {
		token, err = refreshToken(token)
	}
	if err != nil {
		log.Print(err)
		delete(session.Values, "user-info")
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	storeToken(session, token)
	session.Save(r, w)

	u := config.ResourceProxyURL + vars["path"]
	req, err := http.NewRequest(r.Method, u, r.Body)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for k, v := range r.Header {
		req.Header[k] = v
	}

	token.SetAuthHeader(req)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	w.WriteHeader(res.StatusCode)
	// TODO reverse proxy z net/http/httputil????

	defer res.Body.Close()

	h := w.Header()
	for k, v := range res.Header {
		h[k] = v
	}

	_, err = io.Copy(w, res.Body)
	if err != nil {
		log.Println("Error writting response: %s: %s", u, err)
	}
}

func listObjects(token *oauth2.Token, ti *TokenInfo, buckets ...string) map[string]string {
	objects := make(map[string]string)
	for _, bucket := range buckets {
		u := config.ResourceProxyURL + bucket + "/" + ti.Subject + "/list"
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			log.Printf("listObjects: %s", err)
			continue
		}

		token.SetAuthHeader(req)

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("listObjects: %s", err)
			continue
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			log.Printf("listObjects: Request failed: %s: %s", u, res.Status)
			continue
		}

		d := json.NewDecoder(res.Body)
		var slice []string
		if err = d.Decode(&slice); err != nil {
			log.Printf("listObjects: %s", err)
			continue
		}

		for _, s := range slice {
			name := bucket + ":" + s[len(ti.Subject)+1:]
			path := bucket + "/" + s
			objects[name] = path
		}
	}

	return objects
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.New(r, "demo-app-session")
	ui := getUserInfo(session)
	var ti *TokenInfo
	if ui == nil || !ui.LoggedIn {
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	} else {
		token, err := refreshToken(ui.Token)
		if err != nil {
			log.Print(err)
			ui.LoggedIn = false
			ui.Token = nil
		} else {
			ui.Token = token
		}
		session.Values["user-info"] = ui

		if ui.LoggedIn {
			if ti, err = getOAuth2TokenInfo(ui.Token); err != nil {
				log.Printf("Error introspecting token: %s", err)
			}
		}
	}
	session.Save(r, w)

	if !ui.LoggedIn {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseMultipartForm(32 << 20)
		if err != nil {
			log.Printf("Error parsing form: %s", err)
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}

		file, handler, err := r.FormFile("uploadfile")
		if err != nil {
			fmt.Println("Error uploading file: %s", err)
			http.Error(w, "Error uploading form", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		filename := r.Form.Get("filename")
		if filename == "" {
			log.Println("Empty `filename` input")
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		} else {
			filename = strings.Trim(filename, "/")
		}

		u := config.ResourceProxyURL + "demo/" + ti.Subject + "/" + filename + "/create"
		req, err := http.NewRequest(http.MethodPost, u, file)
		if err != nil {
			log.Print(err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", handler.Header.Get("Content-Type"))

		ui.Token.SetAuthHeader(req)

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Print(err)
			http.Error(w, "Upload failed", http.StatusBadGateway)
			return
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusCreated {
			log.Printf("Request failed: %s: %s", u, res.Status)
		}

		w.WriteHeader(res.StatusCode)
		w.Header().Set("Content-Type", res.Header.Get("Content-Type"))
		_, err = io.Copy(w, res.Body)
		if err != nil {
			log.Print(err)
		}

		return
	}

	executeTemplate(w, "templates/upload.html", nil)
}

func executeTemplate(w http.ResponseWriter, templatePath string, data map[string]interface{}) {
	t, err := template.ParseFiles(templatePath)
	if err == nil {
		err = t.Execute(w, data)
	}
	if err != nil {
		log.Print(err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
