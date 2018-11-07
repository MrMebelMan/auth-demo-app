package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
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
	"golang.org/x/oauth2"
)

type Config struct {
	IssuerURL        string   `env:"HYDRA_PUBLIC_URL,default=http://blockbook-dev.corp:4444/"`
	RevokeLoginURL   string   `env:"REVOKE_LOGIN_URL,default=http://blockbook-dev.corp:4445/oauth2/auth/sessions/login/"`
	RevokeConsentURL string   `env:"REVOKE_CONSENT_URL,default=http://blockbook-dev.corp:4445/oauth2/auth/sessions/consent/"`
	IntrospectURL    string   `env:"INTROSPECT_URL,default=http://blockbook-dev.corp:4445/oauth2/introspect"`
	ResourceProxyURL string   `env:"RESOURCE_PROXY_URL,default=http://blockbook-dev.corp:4455/api/store/"`
	ListenAddr       string   `env:"LISTEN_ADDR,default=:8080"`
	CallbackURL      string   `env:"CALLBACK_URL,default=http://localhost:8080/callback"`
	Scopes           []string `env:"SCOPES",default=openid;offline;id_token;wallet;demo`
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
	router.HandleFunc("/introspect/{type:token|id_token}", introspectHandler)
	router.HandleFunc("/resource/{path:.*}", resourceHandler)

	http.ListenAndServeTLS(config.ListenAddr, "cert/server.crt", "cert/server.key", router)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"issuerURL": config.IssuerURL,
	}

	session, _ := store.New(r, "demo-app-session")
	if session.Values["token"] != nil {
		data["isAuthenticated"] = true
	}
	session.Save(r, w)

	t := template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html>
<head>
	<title>Auth Demo App</title>
	<meta charset="UTF-8">
</head>
<body>
	<h1>Auth Demo App</h1>
	<p>This is OAuth2 demo application</p>
	<p>
		<ul>
			{{ if .isAuthenticated }}
			<li><a href="/logout">Logout</a></li>
			<li><a href="/introspect/token">Introspect token</a></li>
			<!--><li><a href="/introspect/id_token">Introspect ID token</a></li><-->
			{{else}}<li><a href="/login">Login</a></li>{{end}}
		</ul>
	</p>
	<p>
		<ul>
			<li><a href="/resource/wallet/abc">Resource: wallet/abc</a></li>
			<li><a href="/resource/wallet/def">Resource: wallet/def</a></li>
			<li><a href="/resource/demo/abc">Resource: demo/abc</a></li>
			<li><a href="/resource/demo/def">Resource: demo/def</a></li>
		</ul>
	</p>
	<p>
		<ul>
			<li><a href="{{ .issuerURL }}oauth2/auth/sessions/login/revoke">Revoke login</a></li>
		</ul>
	</p>
	</body>
</html>`))
	t.Execute(w, data)
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

	ui, err := getUserInfo(token)
	if err != nil {
		log.Println("Get user info:", err)
	}

	session.Values["token"], err = json.Marshal(token)
	if err != nil {
		log.Println("Error serializing token:", err)
	}
	session.Values["id_token"] = rawIDToken
	session.Save(r, w)

	var claims map[string]interface{}
	if ui != nil {
		err = ui.Claims(&claims)
		if err != nil {
			log.Print(err)
		}
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<title>Auth Demo App</title>
	<meta charset="UTF-8">
</head>
<body>
	<h1>Auth Demo App</h1>
	<p>Hello %s,<br/>
	you've been logged in!</p>
	<p/>
	<p><a href="/">Go Back</a></p>
	<hr/>
	<p>code: <b>%s</b></p>
	<p>scope: <b>%s</b></p>
	<p>state: <b>%s</b></p>
	<p>
		token:<br/>
		<ul>
			<li>access token: <b>%s</b></li>
			<li>token type: <b>%s</b></li>
			<li>refresh token: <b>%s</b></li>
			<li>expiry: <b>%s</b></li>
		</ul>
	</p>
	<p>
		User info: <br/>
		<ul>
			<li>Subject: <b>%s</b></li>
			<li>Profile: <b>%s</b></li>
			<li>Email: <b>%s</b></li>
			<li>EmailVerified: <b>%t</b></li>
			<li>Claims: <b>%+v</b></li>
		</ul>
	</p>
	<p>
	<details>
	<summary>Raw ID token</summary>
	<p>%s</p>
	</details>
	</p>
</body>
</html>`,
		ui.Subject,
		code, scope, state,
		token.AccessToken, token.TokenType, token.RefreshToken, token.Expiry.String(),
		ui.Subject, ui.Profile, ui.Email, ui.EmailVerified,
		claims,
		rawIDToken)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.New(r, "demo-app-session")

	token, err := loadToken(session)
	if err != nil {
		log.Print(err)
	}

	delete(session.Values, "token")
	delete(session.Values, "id_token")
	session.Save(r, w)

	if token == nil {
		http.Redirect(w, r, "/", http.StatusFound)
	}

	ui, err := getUserInfo(token)
	if err != nil {
		log.Print(err)
	} else {
		revokeConsent(token, ui.Subject)
		revokeLogin(token, ui.Subject)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func loadToken(session *sessions.Session) (token *oauth2.Token, err error) {
	if b, ok := session.Values["token"]; ok {
		if b, ok := b.([]byte); ok {
			err = json.Unmarshal(b, &token)
		} else {
			err = fmt.Errorf("Token value has invalid type: %T", b)
		}
	}
	return
}

func getUserInfo(token *oauth2.Token) (userInfo *oidc.UserInfo, err error) {
	withTimeout(500, func(ctx context.Context) {
		ts := oauth2Config.TokenSource(ctx, token)
		userInfo, err = oidcProvider.UserInfo(ctx, ts)
	})
	return
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
	vars := mux.Vars(r)
	session, _ := store.New(r, "demo-app-session")

	token, err := loadToken(session)
	var toIntrospect string
	if token.Valid() && err == nil {
		switch vars["type"] {
		case "token":
			toIntrospect = token.AccessToken
		case "id_token":
			if s, ok := session.Values["id_token"]; ok {
				if s, ok := s.(string); ok {
					toIntrospect = s
				}
			}
		}
	}

	if toIntrospect == "" || !token.Valid() || err != nil {
		if err != nil {
			log.Print(err)
		}
		delete(session.Values, "token")
		delete(session.Values, "id_token")
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	}

	session.Save(r, w)

	cli := oauth2Config.Client(context.Background(), token)

	form := url.Values{}
	form.Set("token", toIntrospect)
	req, err := http.NewRequest("POST", config.IntrospectURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := cli.Do(req)
	if err != nil {
		log.Print(err)
	} else {
		defer res.Body.Close()
		b, _ := ioutil.ReadAll(res.Body)
		fmt.Fprintln(w, string(b))
	}
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
	if err != nil {
		log.Print(err)
		delete(session.Values, "token")
		delete(session.Values, "id_token")
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	}

	session.Save(r, w)

	cli := oauth2Config.Client(context.TODO(), token)

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

	res, err := cli.Do(req)
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

	// XXX log & hide http errors
	// XXX chunked body
	io.Copy(w, res.Body)
}
