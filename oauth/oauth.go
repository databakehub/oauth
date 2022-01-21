package oauth

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	rcfg "github.com/databakehub/rcfg-client-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/google"
)

const (
	rcfgUrl      = "http://localhost:2222"
	authCallback = "/authcallback"
	authPath     = "/auth"
)

type OAuth struct {
	Rcfg        *rcfg.RcfgClient
	HostAddress string
	SessionName string
	Secrets     map[string]OAuthCredentials
	RedirectTo  string
}

type OAuthCredentials struct {
	ClientId string
	Secret   string
}

type SessionSchema struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	DbId     string `json:"db_id,omitempty"`
}

func SetupOauth(sessionName string, secrets map[string]OAuthCredentials, hostAddress string, redirectTo string) *OAuth {
	rand.Seed(time.Now().UnixNano())

	oauth := &OAuth{
		Rcfg:        rcfg.NewRcfgClient(rcfgUrl, 5*time.Second),
		HostAddress: hostAddress,
		SessionName: sessionName,
		Secrets:     secrets,
		RedirectTo:  redirectTo,
	}
	oauth.setupGoth()
	return oauth
}

func (o *OAuth) setupGoth() {
	// key := string(securecookie.GenerateRandomKey(10))
	// maxAge := 86400 * 2 // 2 days
	// isProd := false     // Set to true when serving over https

	// store := sessions.NewCookieStore([]byte(key))
	// store.MaxAge(maxAge)
	// store.Options.Path = "/"
	// store.Options.HttpOnly = true // HttpOnly should always be enabled
	// store.Options.Secure = isProd
	// gothic.Store = store

	callback := o.HostAddress + authCallback
	goog, ok := o.Secrets["google"]
	if ok {
		goth.UseProviders(google.New(goog.ClientId, goog.Secret, callback, "email", "profile", "openid"))
	}
	fb, ok := o.Secrets["facebook"]
	if ok {
		goth.UseProviders(facebook.New(fb.ClientId, fb.Secret, callback, "email", "public_profile"))
	}
}

func (o *OAuth) AuthHandler(w http.ResponseWriter, req *http.Request) {
	gothic.BeginAuthHandler(w, req)
}

func (o *OAuth) CallbackHandler(w http.ResponseWriter, req *http.Request) {
	user, err := gothic.CompleteUserAuth(w, req)
	token := ""
	if err != nil {
		log.Println(err)
	} else {
		token = string(securecookie.GenerateRandomKey(10))
		log.Println("Random string gen: " + token)
		ss := extractSessionSchemaFromGoth(user)
		json, err := sessionSchemaToJson(ss)
		if err != nil {
			log.Println(err)
		} else {
			o.Rcfg.SetWithTTL(o.SessionName, token, json, "5")
		}
	}
	http.Redirect(w, req, o.RedirectTo+"?oauth_token="+token, http.StatusTemporaryRedirect)
}

func (o *OAuth) AuthCheckHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	t, ok := vars["token"]
	if !ok {
		errorHttpForbidden(w, fmt.Errorf("missing token in path /authcheck/{token}"))
		return
	}
	v, err := o.Rcfg.Get(o.SessionName, t)
	if err != nil || v == "" {
		errorHttpForbidden(w, fmt.Errorf("invalid session: %s", err))
		return
	}
	// write v to response
	var ss SessionSchema
	err = json.Unmarshal([]byte(v), &ss)
	if err != nil {
		errorHttpForbidden(w, fmt.Errorf("session parse error: %s", err))
		return
	}
	b, err := json.Marshal(ss)
	if err != nil {
		errorHttpForbidden(w, fmt.Errorf("session marshal error: %s", err))
		return
	}
	w.Write(b)
}

func errorHttpForbidden(w http.ResponseWriter, err error) {
	http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusForbidden)
}

func (x *OAuth) SetupMuxRouter(r *mux.Router) {
	r.HandleFunc("/auth/{provider}", x.AuthHandler).Methods("GET")
	r.HandleFunc("/authcallback", x.CallbackHandler).Methods("GET")
	r.HandleFunc("/authcheck/{token}", x.AuthCheckHandler).Methods("GET")
}

func extractSessionSchemaFromGoth(user goth.User) *SessionSchema {
	return &SessionSchema{
		Email:    user.Email,
		Name:     user.Name,
		Provider: user.Provider,
		DbId:     "",
	}
}

func sessionSchemaToJson(s *SessionSchema) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return url.QueryEscape(string(b)), nil
}

func parseSessionSchemaFromJson(s string) (*SessionSchema, error) {
	ss := &SessionSchema{}
	un, err := url.QueryUnescape(s)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(un), ss)
	if err != nil {
		return nil, err
	}
	return ss, nil
}
