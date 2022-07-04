package oauth

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	rcfg "github.com/databakehub/rcfg-client-go"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/google"
)

const (
	authCallback = "/authcallback"
	authPath     = "/auth"
	tokenLength  = 15
)

type OAuth struct {
	Rcfg        *rcfg.RcfgClient
	HostAddress string
	SessionName string
	Secrets     map[string]OAuthCredentials
	RedirectTo  string
	TTL         string
}

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
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

func NewOauth(
	rcfgUrl,
	sessionName string,
	secrets map[string]OAuthCredentials,
	hostAddress string,
	redirectTo string,
	ttl string) *OAuth { // ttl is in minutes
	rand.Seed(time.Now().UnixNano())

	oauth := &OAuth{
		Rcfg:        rcfg.NewRcfgClient(rcfgUrl, 5*time.Second),
		HostAddress: hostAddress,
		SessionName: sessionName,
		Secrets:     secrets,
		RedirectTo:  redirectTo,
		TTL:         ttl,
	}
	oauth.setupGoth()
	return oauth
}

func (o *OAuth) setupGoth() {
	key := string(securecookie.GenerateRandomKey(10))
	maxAge := 86400 * 2 // 2 days
	isProd := true      // Set to true when serving over https

	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true // HttpOnly should always be enabled
	store.Options.Secure = isProd
	gothic.Store = store

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
		ss := extractSessionSchemaFromGoth(user)
		token = generateRandomStringFromEmail(ss.Email)
		log.Println("Random string gen: " + token)
		json, err := sessionSchemaToJson(ss)
		if err != nil {
			log.Println(err)
		} else {
			o.Rcfg.SetWithTTL(o.SessionName, token, json, o.TTL)
		}
	}
	if token == "" {
		http.Redirect(w, req, o.RedirectTo, http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, req, o.RedirectTo+"?oauth_token="+token, http.StatusTemporaryRedirect)
	}
}

func (o *OAuth) AuthCheckHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	t, ok := vars["token"]
	log.Println("Token: " + t)
	if !ok {
		errorHttpForbidden(w, fmt.Errorf("missing token in path /authcheck/{token}"))
		return
	}
	v, err := o.Rcfg.Get(o.SessionName, t)
	log.Println("Rcfg value: " + v)
	if err != nil || v == "" {
		errorHttpForbidden(w, fmt.Errorf("invalid session: %s", err))
		return
	}
	// write v to response
	ss, err := parseSessionSchemaFromJson(v)
	log.Println("Session parsed", ss)
	if err != nil {
		errorHttpForbidden(w, fmt.Errorf("session parse error: %s", err))
		return
	}
	b, err := json.Marshal(ss)
	log.Println("Session marshalled", string(b))
	if err != nil {
		errorHttpForbidden(w, fmt.Errorf("session marshal error: %s", err))
		return
	}
	w.Write(b)
}

func (x *OAuth) SetupMuxRouter(r *mux.Router) {
	r.HandleFunc("/auth/{provider}", x.AuthHandler).Methods("GET")
	r.HandleFunc("/authcallback", x.CallbackHandler).Methods("GET")
	r.HandleFunc("/authcheck/{token}", x.AuthCheckHandler).Methods("GET")
}

func extractGinHandlerFromHandler(f func(w http.ResponseWriter, req *http.Request)) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Forward all path params to muxParams
		mapOfParams := make(map[string]string)
		for _, param := range c.Params {
			mapOfParams[param.Key] = param.Value
		}
		reqWithParams := mux.SetURLVars(c.Request, mapOfParams)
		f(c.Writer, reqWithParams)
	}
}

func (x *OAuth) SetupGinRouter(r *gin.Engine) {
	r.GET("/auth/:provider", extractGinHandlerFromHandler(x.AuthHandler))
	r.GET("/authcallback", extractGinHandlerFromHandler(x.CallbackHandler))
	r.GET("/authcheck/:token", extractGinHandlerFromHandler(x.AuthCheckHandler))
}

// Get routes to be used by the router
//
// Sample usage:
//
// router.
//   Methods(route.Method).
//   Path(route.Pattern).
//   Name(route.Name).
//   Handler(handler)

func (x *OAuth) GetRoutes() []Route {
	return []Route{
		{
			Name:        "ProviderAuth",
			Method:      "GET",
			Pattern:     authPath + "/{provider}",
			HandlerFunc: x.AuthHandler,
		},
		{
			Name:        "AuthCallback",
			Method:      "GET",
			Pattern:     authCallback,
			HandlerFunc: x.CallbackHandler,
		},
		{
			Name:        "AuthCheck",
			Method:      "GET",
			Pattern:     authPath + "/{token}",
			HandlerFunc: x.AuthCheckHandler,
		},
	}
}

func (x *OAuth) SetDbIdForToken(token string, dbId string) error {
	v, err := x.Rcfg.Get(x.SessionName, token)
	if err != nil {
		return err
	}
	ss, err := parseSessionSchemaFromJson(v)
	if err != nil {
		return err
	}
	ss.DbId = dbId
	json, err := sessionSchemaToJson(ss)
	if err != nil {
		return err
	}
	x.Rcfg.SetWithTTL(x.SessionName, token, json, x.TTL)
	return nil
}

func (x *OAuth) AuthCheck(w http.ResponseWriter, req *http.Request) (*SessionSchema, error) {
	token := req.Header.Get("Authorization")
	if token == "" {
		e := fmt.Errorf("no oauth token")
		errorHttpForbidden(w, e)
		return nil, e
	}
	ss, err := x.GetSessionSchema(token)
	if err != nil {
		log.Println("Auth check error: ", err)
		e := fmt.Errorf("do I know you? " + err.Error())
		errorHttpForbidden(w, e)
		return nil, e
	}
	return ss, err
}

func (x *OAuth) BasicAuthCheck(w http.ResponseWriter, req *http.Request) (*SessionSchema, error) {
	token := req.Header.Get("Authorization")
	if token == "" {
		token = req.Header.Get("authorization")
	}
	if token == "" {
		return nil, fmt.Errorf("no authorization token")
	}
	token = strings.TrimPrefix(token, "Basic")
	token = strings.TrimSpace(token)
	// base64 decode
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		errorHttpForbidden(w, fmt.Errorf("could not parse token"))
		return nil, err
	}
	decodedString := string(decoded)
	token = strings.TrimPrefix(decodedString, "u:")
	token = strings.TrimSpace(token)
	if token == "" {
		e := fmt.Errorf("no oauth token")
		errorHttpForbidden(w, e)
		return nil, e
	}
	ss, err := x.GetSessionSchema(token)
	if err != nil {
		log.Println("Auth check error: ", err)
		e := fmt.Errorf("do I know you? " + err.Error())
		errorHttpForbidden(w, e)
		return nil, e
	}
	return ss, err
}

func (x *OAuth) GetSessionSchema(token string) (*SessionSchema, error) {
	s, err := x.Rcfg.Get(x.SessionName, token)
	if err != nil {
		return nil, err
	}
	return parseSessionSchemaFromJson(s)
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

func parseSessionSchemaFromJson(tokenSession string) (*SessionSchema, error) {
	mapS := make(map[string]string)
	err := json.Unmarshal([]byte(tokenSession), &mapS)
	if err != nil {
		return nil, err
	}
	s := ""
	for k := range mapS {
		s = mapS[k]
		break
	}
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

func generateRandomStringFromEmail(email string) string {
	if len(email) < 1 {
		return generateRandomString(tokenLength)
	}
	s := time.Now().Format("2006-01-02") + email
	rs := fmt.Sprintf("%x", md5.Sum([]byte(s)))
	if len(rs) >= tokenLength {
		return rs[:tokenLength]
	} else {
		return rs
	}
}

func generateRandomString(l int) string {
	availableChars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, l)
	for i := range b {
		b[i] = availableChars[rand.Intn(len(availableChars))]
	}
	return string(b)
}

func errorHttpForbidden(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, err.Error())))
}
