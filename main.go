package traefikapim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config the plugin configuration.

const StaticApiKeyName = "X-AUTH-API"
const AuthorizationHeader = "Authorization"
const TokenType = "tokenType"
const BearerPrefix = "Bearer "
const AppId = "appId"

const Jwt = "JWT"
const Oauth2 = "OAUTH2"
const None = "NONE"
const Static = "STATIC"

type OAuth2Client struct {
	ServerURL string
	ClientID  string
	Secret    string
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type JWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}
type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWTClaims struct {
	Exp int64  `json:"exp"`
	Jti string `json:"preferred_username"`
}

type GlobalItems struct {
	JwtEnryptionType       string `json:"jwtEnryptionType"`
	JwtEnryptionSecret     string `json:"jwtEnryptionSecret"`
	JwtEnryptionPrivateKey string `json:"jwtEnryptionPrivateKey"`
	JwtJks                 string `json:"jwtJks"`
	TokenUrl               string `json:"tokenUrl"`
	Secret                 string `json:"secret"`
	ClientId               string `json:"clientId"`
}

type UrlInfo struct {
	Url           string
	Method        string
	AddHeaders    map[string]string `json:"addHeaders"`
	RemoveHeaders []string          `json:"removeHeaders"`
	JspathRequest string            `json:"jspathRequest"`
}

type Urls []UrlInfo

type Application struct {
	Id                   string `json:"id"`
	Enable               bool   `json:"enable"`
	ClientId             string `json:"clientId"`
	Oauth2Url            string `json:"oauth2Url"`
	AllowedIps           string `json:"allowedIps"`
	Secured              bool   `json:"secured"`
	Urls                 Urls   `json:"url"`
	Method               string `json:"method"`
	SecureHeaderName     string `json:"secureHeaderName"`
	SecureHeaderValue    string `json:"secureHeaderValue"`
	SecurityType         string `json:"securityType"`
	SendOauth2AuthHeader bool   `json:"sendOauth2AuthHeader"`
}

type Applications []Application

type Config struct {
	Global       GlobalItems  `json:"global"`
	Applications Applications `json:"applications"`
}

func CreateConfig() *Config {
	return &Config{}
}

type Traefikapim struct {
	next http.Handler
	name string
	cfg  *Config
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Traefikapim{
		next: next,
		name: name,
		cfg:  config,
	}, nil
}

func GetFieldFromJWT(tokenString, field string) (interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	value, exists := claims[field]
	if !exists {
		return nil, fmt.Errorf("field '%s' not found", field)
	}

	return value, nil
}

func FindApplicationyApiAccessKey(apps []Application, apiAccessKey string) *Application {
	for _, app := range apps {
		if app.SecureHeaderValue == apiAccessKey {
			return &app
		}
	}
	return nil
}

func FindApplicationyByStaticAuthType(apps []Application) []Application {
	appsRes := make([]Application, 0)
	for _, app := range apps {
		if app.SecureHeaderName == StaticApiKeyName {
			appsRes = append(appsRes, app) // Return pointer to first match
		}
	}
	return appsRes // Return nil if no match found
}

func FindApplicationyAppId(apps []Application, appId string) *Application {
	for _, app := range apps {
		if app.Id == appId {
			return &app // Return pointer to first match
		}
	}
	return nil // Return nil if no match found
}

func isUrlBelongToAnApp(app *Application, path string, method string) bool {
	for _, url := range app.Urls {
		if url.Url == path && url.Method == method {
			return true
		}
	}
	return false
}

func GetUrlInfo(app *Application, path string, method string) *UrlInfo {
	fmt.Printf("app length in GetUrlInfo %d for %v", len(app.Urls), app)
	for _, url := range app.Urls {
		fmt.Printf("CCCCCCC")
		if url.Url == path && url.Method == method {
			return &url
		}
	}
	return nil
}

func GetApplication(a *Traefikapim, headers http.Header) []Application {

	appsRes := make([]Application, 0)

	apps := a.cfg.Applications

	if len(apps) != 0 {
		if headers.Get(AuthorizationHeader) != "" {
			token := strings.TrimPrefix(headers.Get(AuthorizationHeader), BearerPrefix)

			tokenType, err := GetFieldFromJWT(token, TokenType)
			if err != nil {
				fmt.Printf("Error while getting token type from token %s, %v", token, err)
			} else {
				if tokenType == Jwt {
					applicationId, errAppId := GetFieldFromJWT(token, AppId)
					if errAppId != nil {
						fmt.Printf("No found app in config for this Jwt Token %s, %v", token, errAppId)
					} else {
						fmt.Printf("Get App JWT using AppId %s", applicationId.(string))
						appsRes = append(appsRes, *FindApplicationyAppId(apps, applicationId.(string)))
					}

				} else if tokenType == Oauth2 {
					applicationId, errAppId := GetFieldFromJWT(token, AppId)
					if errAppId != nil {
						fmt.Printf("No found app in config for this Oauth2 Token %s, %v", token, errAppId)
					} else {
						fmt.Printf("Get App Oauth2 using AppId %s", applicationId.(string))
						appsRes = append(appsRes, *FindApplicationyAppId(apps, applicationId.(string)))
					}
				}
			}

		} else if headers.Get(StaticApiKeyName) != "" {
			appsRes = FindApplicationyByStaticAuthType(apps)
		} else {
		}

	}

	return appsRes
}

func getPublicKey(jwksURL string) (*rsa.PublicKey, error) {
	fmt.Println("Get Public Key from ", jwksURL)
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks JWKS
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, err
	}

	key := jwks.Keys[0]

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}

	var e int
	for _, b := range eBytes {
		e = (e << 8) + int(b)
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}

	return publicKey, nil
}

func validateJWT(tokenString string, publicKey *rsa.PublicKey) (bool, error) {
	_, claims, signature, err := parseJWT(tokenString)
	if err != nil {
		return false, err
	}

	if time.Now().Unix() > claims.Exp {
		return false, errors.New("token is expired")
	}

	hasher := sha256.New()
	hasher.Write([]byte(strings.Join(strings.Split(tokenString, ".")[0:2], ".")))
	hashed := hasher.Sum(nil)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signature)
	if err != nil {
		return false, err
	}

	return true, nil
}

func parseJWT(tokenString string) (header JWTHeader, claims JWTClaims, signature []byte, err error) {

	/*if entry, exists := jwtCache.Get("pubk"); exists {
		fmt.Println("Cache hit! Returning cached result.")
		return entry.header, entry.claims, entry.signature, nil
	}*/

	fmt.Println("Cache miss! Parsing JWT and caching result.")

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		err = errors.New("invalid JWT format")
		return
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		err = errors.New("decode Jwt Error")
		return
	}
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		err = errors.New("decode Claim Error Part1")
		return
	}
	err = json.Unmarshal(claimsBytes, &claims)
	if err != nil {
		err = errors.New("decode Claim Error Part2")
		return
	}

	// Decode signature
	signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return
	}
	fmt.Println("Jwt Token is parsed succesfuly")
	return
}

func checkOauth2(u *Traefikapim, rw http.ResponseWriter, authHeader string) error {
	var publicKey *rsa.PublicKey
	var err error
	if u.cfg.Global.JwtJks != "" {
		publicKey, err = getPublicKey(u.cfg.Global.JwtJks)
		if err != nil {
			fmt.Printf("cannot getb the public key")
			return errors.New("cannot getb the public key")
		} else {
			if authHeader == "" {
				fmt.Println("not Authorized: Authorization header is missing")
				return errors.New("not Authorized: Authorization header is missing")
			} else if !strings.HasPrefix(authHeader, "Bearer ") {
				fmt.Println("not Authorized: Invalid Authorization header format")
				return errors.New("not Authorized: Invalid Authorization header format")
			} else {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				valid, err := validateJWT(token, publicKey)
				if err != nil {
					fmt.Println("Not Authorized: Error validating JWT")
					return errors.New("not Authorized: Error validating JWT")
				} else if valid {
					return nil
				} else {
					fmt.Println("Not Authorized: Not Authorized")
					return errors.New("not Authorized: Not Authorized")
				}
			}
		}
	}
	fmt.Printf("Cannot getb the public key, jwks url is not found !")
	return errors.New("not Authorized: Not Authorized")
}

func ShowNoAppError(rw http.ResponseWriter) {
	fmt.Println("App : NoApp")
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(rw).Encode(map[string]string{
		"error":   "Unauthorized",
		"message": "Not Authorized: No app",
	})
}

func ShowNoAuthError(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(rw).Encode(map[string]string{
		"error":   "Unauthorized",
		"message": "Not Authorized",
	})
}

func ShowForbiddenNotAllowedIPError(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(rw).Encode(map[string]string{
		"error":   "Forbidden",
		"message": "IP address is not allowed !",
	})
}
func ShowNoNotRecognizedAuthTypeError(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(rw).Encode(map[string]string{
		"error":   "Unauthorized",
		"message": "Not recognized auth type",
	})
}

func parseJsonPath(path string) ([]interface{}, error) {
	if !strings.HasPrefix(path, "$") {
		return nil, fmt.Errorf("path must start with $")
	}
	path = path[1:] // Remove the "$" prefix
	var steps []interface{}
	pos := 0
	for pos < len(path) {
		for pos < len(path) && path[pos] == '.' {
			pos++
		}
		if pos >= len(path) {
			break
		}
		if path[pos] == '[' {
			close := strings.IndexByte(path[pos:], ']')
			if close == -1 {
				return nil, fmt.Errorf("unclosed [ at position %d", pos)
			}
			idxStr := path[pos+1 : pos+close]
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				return nil, fmt.Errorf("invalid index: %s at position %d", idxStr, pos+1)
			}
			steps = append(steps, idx)
			pos += close + 1
		} else {
			start := pos
			for pos < len(path) && path[pos] != '.' && path[pos] != '[' {
				pos++
			}
			field := path[start:pos]
			steps = append(steps, field)
		}
	}
	return steps, nil
}

func evaluate(jsonData interface{}, steps []interface{}) (interface{}, error) {
	current := jsonData
	for _, step := range steps {
		if current == nil {
			return nil, fmt.Errorf("cannot proceed on nil")
		}
		switch s := step.(type) {
		case string:
			m, ok := current.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("expected map, got %T", current)
			}
			val, ok := m[s]
			if !ok {
				return nil, fmt.Errorf("field %s not found", s)
			}
			current = val
		case int:
			arr, ok := current.([]interface{})
			if !ok {
				return nil, fmt.Errorf("expected array, got %T", current)
			}
			if s < 0 || s >= len(arr) {
				return nil, fmt.Errorf("index %d out of range", s)
			}
			current = arr[s]
		default:
			return nil, fmt.Errorf("invalid step type: %T", step)
		}
	}
	return current, nil
}

func getBodyRequestJsonPathResult(path string, data interface{}) (string, error) {

	if path == "" || data == nil {
		return "", nil
	}

	steps, err := parseJsonPath(path)

	if err != nil {
		fmt.Println("Error parsing path:", err)
		return "", err
	}

	result, err := evaluate(data, steps)

	if err != nil {
		fmt.Println("Error evaluating path:", err)
		return "", err
	}
	return result.(string), nil
}

func processJSON(data interface{}, dataJSON string, headers http.Header, queries url.Values) interface{} {
	var result string

	var template2 map[string]interface{}
	if err := json.Unmarshal([]byte(dataJSON), &template2); err != nil {
		panic(err)
	}

	switch v := data.(type) {

	case map[string]interface{}:
		for key, value := range v {
			v[key] = processJSON(value, dataJSON, headers, queries)
		}
		return v
	case []interface{}:
		// If it's a slice, iterate over its elements.
		for i, item := range v {
			v[i] = processJSON(item, dataJSON, headers, queries)
		}
		return v
	case string:
		if strings.HasPrefix(v, "$.") {
			result, _ = getBodyRequestJsonPathResult(v, template2)

			return result
		}

		if strings.HasPrefix(v, "_$q.") {
			headerName := strings.Replace(v, "_$q.", "", 1)
			result := queries.Get(headerName)
			return result

		}

		if strings.HasPrefix(v, "_$h.") {
			headerName := strings.Replace(v, "_$h.", "", 1)
			result := headers.Get(headerName)
			return result

		}

		if strings.HasPrefix(v, "_$c.") {
			AuthHeader := strings.TrimPrefix(headers.Get(AuthorizationHeader), BearerPrefix)
			headerName := strings.Replace(v, "_$c.", "", 1)

			if AuthHeader != "" {

				claimField, er := GetFieldFromJWT(AuthHeader, headerName)
				if er == nil {
					return claimField

				} else {
					return nil
				}

			} else {
				return nil
			}
		}

		return v
	default:
		return v
	}
}

func updateNativeRequest(config UrlInfo, ddata []byte, headers http.Header, queries url.Values) []byte {

	if len(ddata) > 0 {

		dataJSON := string(ddata)

		var template map[string]interface{}
		if err := json.Unmarshal([]byte(config.JspathRequest), &template); err != nil {
			panic(err)
		}

		processedJSON := processJSON(template, dataJSON, headers, queries)

		output, err := json.MarshalIndent(processedJSON, "", "  ")
		if err != nil {
			panic(err)
		}

		return output

	} else {
		return ddata
	}

}

func setHeaderAsString(req *http.Request, key string, claimField interface{}) {

	switch v := claimField.(type) {
	case string:
		req.Header.Set(key, v)
	case int:
		req.Header.Set(key, strconv.Itoa(v))
	case bool:
		req.Header.Set(key, strconv.FormatBool(v))
	case float64:
		req.Header.Set(key, strconv.FormatFloat(v, 'f', -1, 64))
	default:

		req.Header.Set(key, fmt.Sprintf("%v", v))
	}
}

func changeRequestHeaders(config UrlInfo, req *http.Request, ddata []byte, headers http.Header) {

	if len(config.AddHeaders) > 0 {

		for key, value := range config.AddHeaders {
			if strings.HasPrefix(value, "$.") {

				if len(ddata) > 0 {

					dataJSON := string(ddata)
					var template2 map[string]interface{}
					if err := json.Unmarshal([]byte(dataJSON), &template2); err != nil {
						panic(err)
					}
					toto, _ := getBodyRequestJsonPathResult(value, template2)
					setHeaderAsString(req, key, toto)

				} else {
					setHeaderAsString(req, key, "")
				}

			}

			if strings.HasPrefix(value, "_$q.") {
				headerName := strings.Replace(value, "_$q.", "", 1)
				result := req.URL.Query().Get(headerName)
				setHeaderAsString(req, key, result)

			}

			if strings.HasPrefix(value, "_$c.") {

				AuthHeader := strings.TrimPrefix(headers.Get(AuthorizationHeader), BearerPrefix)
				headerName := strings.Replace(value, "_$c.", "", 1)

				if AuthHeader != "" {
					claimField, er := GetFieldFromJWT(AuthHeader, headerName)

					if er == nil {
						setHeaderAsString(req, key, claimField)

					} else {
						setHeaderAsString(req, key, "")
					}

				} else {
					setHeaderAsString(req, key, "")
				}
			} else {
				setHeaderAsString(req, key, value)
			}
		}
	}

	if len(config.RemoveHeaders) > 0 {
		fmt.Println("RemoveHeaders", config.RemoveHeaders)

		for _, key := range config.RemoveHeaders {
			req.Header.Del(key)
		}

	}
}

func NewOAuth2Client(serverURL, clientID, secret string) *OAuth2Client {
	return &OAuth2Client{
		ServerURL: serverURL,
		ClientID:  clientID,
		Secret:    secret,
	}
}

func (c *OAuth2Client) GetAccessToken() (*TokenResponse, error) {
	tokenURL := c.ServerURL

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.ClientID)
	data.Set("client_secret", c.Secret)

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &tokenResp, nil
}

func getToken(u *Traefikapim) string {
	client := NewOAuth2Client(
		u.cfg.Global.TokenUrl,
		u.cfg.Global.ClientId,
		u.cfg.Global.Secret,
	)

	token, err := client.GetAccessToken()
	if err != nil {
		fmt.Printf("Error while getting access token : %v\n", err)
		return ""
	}
	return "Bearer " + token.AccessToken
}

func isIPWhitelisted(ipStr, whitelist string) bool {
	whitelistIPs := strings.Split(whitelist, ",")

	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}

	for _, allowedIP := range whitelistIPs {
		allowed := net.ParseIP(strings.TrimSpace(allowedIP))
		if allowed != nil && ip.Equal(allowed) {
			return true
		}
	}

	return false
}

func isRequestWhitelisted(r *http.Request, whitelist string) bool {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil {
		clientIP = r.RemoteAddr
	}

	fmt.Printf("___PROXY Direct IP Client %s", clientIP)

	if isIPWhitelisted(clientIP, whitelist) {
		return true
	}

	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")

		if len(ips) > 0 {
			originIP := strings.TrimSpace(ips[0])
			if isIPWhitelisted(originIP, whitelist) {
				return true
			}
		}
	}

	return false
}

func (a *Traefikapim) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	apps := GetApplication(a, req.Header)
	var app *Application
	path := req.URL.Path
	method := req.Method
	var headers http.Header
	var queries url.Values

	headers = req.Header
	queries = req.URL.Query()

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer req.Body.Close()

	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))

	//Stage 1 : Auth

	if len(apps) == 1 { //Oauth2 or Jwt
		app = &apps[0]
		fmt.Printf("Selected App 1 : %s\n", app.Id)

		if app.Enable {

			fmt.Printf("Path : %s, Method : %s\n", path, method)

			if isUrlBelongToAnApp(app, path, method) {
				fmt.Printf("Path : %s, Method : %s belong to app %s\n", path, method, app.Id)

				if app.Secured {
					if app.SecurityType == Oauth2 {
						err := checkOauth2(a, rw, req.Header.Get(AuthorizationHeader))
						if err != nil {
							fmt.Printf("Auth Error : %v", err)
							ShowNoAuthError(rw)
							return
						}
					} else if app.SecurityType == Jwt {

					} else if app.SecurityType == Static {

						if app.SecureHeaderValue != req.Header.Get(StaticApiKeyName) {
							ShowNoAuthError(rw)
							return
						} else {
							fmt.Printf("Connected as statc")
						}

					} else {
						fmt.Printf("Not recognized auth type : %s", app.SecurityType)
						ShowNoNotRecognizedAuthTypeError(rw)
						return
					}
				}

			} else {
				fmt.Printf("Path and/or Method not match the given application : %s", app.Id)
				ShowNoAppError(rw)
				return
			}
		} else {
			fmt.Printf("App %s is not enabled !\n", app.Id)
		}

	} else if len(apps) > 1 { // static token
		app = FindApplicationyApiAccessKey(apps, req.Header.Get(StaticApiKeyName))
		fmt.Printf("Selected App 2 : %s\n", app.Id)

		if app.Secured {
			if app != nil {
				ShowNoAuthError(rw)
				return
			} else {
				if app.Enable {
					fmt.Printf("Connected as statc")
				} else {
					fmt.Printf("App %s is not enabled !\n", app.Id)
				}
			}
		}
	} else {
		ShowNoAppError(rw)
		return
	}

	//Stage 2 : Whitelist

	if app.AllowedIps != "" {

		if !isRequestWhitelisted(req, app.AllowedIps) {
			ShowForbiddenNotAllowedIPError(rw)
			return
		}

	}

	//Stage 2 : Transformations
	urlInfo := GetUrlInfo(app, path, method)
	fmt.Printf("Check Path UrlInfo  for app %s", app.Id)

	if urlInfo != nil {
		fmt.Printf("Path UrlInfo is found for %s %s, for app %s", method, path, app.Id)
		changeRequestHeaders(*urlInfo, req, bodyBytes, headers)

		if app.SendOauth2AuthHeader {
			req.Header.Set("Authorization", getToken(a))
		}

		if urlInfo.JspathRequest != "" {
			erest := updateNativeRequest(*urlInfo, bodyBytes, headers, queries)

			if len(erest) > 0 {
				req.Body = io.NopCloser(bytes.NewReader(erest))

				contentLength := len(erest)
				req.ContentLength = int64(contentLength)
				req.Header.Set("Content-Length", strconv.Itoa(contentLength))
			}

		}

	} else {
		fmt.Printf("Path UrlInfo not found for %s %s", method, path)
	}

	a.next.ServeHTTP(rw, req)

}
