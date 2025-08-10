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
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Config the plugin configuration.

const AuthorizationHeader = "Authorization"
const TokenType = "tokenType"
const BearerPrefix = "Bearer "
const BasicPrefix = "Basic "
const AppId = "appId"

const JwtTokenRequestor = "GetJWTToken"
const Oauth2TokenRequestor = "GetOauth2Token"
const Oauth2 = "OAUTH2"
const None = "NONE"
const Static = "STATIC"
const Basic = "BASIC"

const XGatewayApiKey = "x-Gateway-APIKey"

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
	TokenUrl               string `json:"tokenUrl"`
	Secret                 string `json:"secret"`
	ClientId               string `json:"clientId"`
	SecureHeaderName       string `json:"secureHeaderName"`
}

type UrlInfo struct {
	Url           string
	Method        string
	AddHeaders    map[string]string `json:"addHeaders"`
	RemoveHeaders []string          `json:"removeHeaders"`
	JspathRequest string            `json:"jspathRequest"`
	JsPathUri     string            `json:"jsPathUri"`
	JsPathVarable string            `json:"jsPathVarable"`
}

type Urls []UrlInfo

type Application struct {
	Id                string `json:"id"`
	Enable            bool   `json:"enable"`
	ClientId          string `json:"clientId"`
	AllowedIps        string `json:"allowedIps"`
	Secured           bool   `json:"secured"`
	Urls              Urls   `json:"url"`
	Method            string `json:"method"`
	SecureHeaderName  string `json:"secureHeaderName"`
	SecureHeaderValue string `json:"secureHeaderValue"`
	SecurityType      string `json:"securityType"`

	BaseBasicToken       string `json:"baseBasicToken"`
	SendOauth2AuthHeader bool   `json:"sendOauth2AuthHeader"`

	UrlToken           string `json:"urlToken"`
	ExposedGetTokenUrl string `json:"exposedGetTokenUrl"`

	JwtJks string `json:"jwtJks"`
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

func FindApplicationyByStaticAuthType(a *Traefikapim, apps []Application, secureHeadervalue string) []Application {
	appsRes := make([]Application, 0)
	for _, app := range apps {
		if app.SecureHeaderName == a.cfg.Global.SecureHeaderName && app.SecureHeaderValue == secureHeadervalue {
			appsRes = append(appsRes, app)
		}
	}
	return appsRes
}

func FindApplicationyAppId(apps []Application, appId string) *Application {
	for _, app := range apps {
		if app.Id == appId {
			return &app
		}
	}
	return nil
}

func isUrlBelongToAnApp(app *Application, path string, method string) bool {
	for _, url := range app.Urls {
		fmt.Printf("LOLAAAAA %v,%v => %v", url.Url, path, strings.Contains(url.Url, path))
		if strings.Contains(path, url.Url) && url.Method == method {
			return true
		}
	}
	return false
}

func getTokenApp(apps []Application, appId string) *Application {
	for _, app := range apps {
		if app.Secured == false && app.Id == appId {
			return &app
		}
	}
	return nil
}

func GetUrlInfo(app *Application, path string, method string) *UrlInfo {
	fmt.Printf("app length in GetUrlInfo %d for %v", len(app.Urls), app)
	for _, url := range app.Urls {
		fmt.Printf("CCCCCCC %d", url)
		if strings.Contains(path, url.Url) && url.Method == method {
			return &url
		}
	}
	return nil
}

func FindApplicationyByBasicAuthType(a *Traefikapim, apps []Application, token string) []Application {
	appsRes := make([]Application, 0)
	fmt.Printf("Basic Auth %s, length app : %v", token, len(apps))

	for _, app := range apps {
		fmt.Printf("app.SecurityType : %s,   app.BaseBasicToken : %s == %s", Basic, app.BaseBasicToken, token)

		if app.SecurityType == Basic && app.BaseBasicToken == token {
			fmt.Printf("BASIC APP EXIST")

			appsRes = append(appsRes, app)
		}
	}
	return appsRes
}

func ParseBasicAuth(token string) (string, string, error) {

	fmt.Printf("Try to decrypt %s", token)

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))

	if err != nil {
		return "", "", err
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", errors.New("invalid basic auth format")
	}

	return parts[0], parts[1], nil
}

func MaskPassword(password string) string {
	if len(password) <= 3 {
		return password
	}
	return password[:3] + strings.Repeat("*", len(password)-3)
}
func CompareJSONInterfaces(a, b interface{}) bool {
	jsonStrA, okA := a.(string)
	jsonStrB, okB := b.(string)
	if !okA || !okB {
		fmt.Errorf("both inputs must be JSON strings, got types %T and %T", a, b)
		return false
	}
	var dataA, dataB interface{}
	if err := json.Unmarshal([]byte(jsonStrA), &dataA); err != nil {
		fmt.Errorf("invalid JSON in first argument: %v", err)
		return false
	}
	if err := json.Unmarshal([]byte(jsonStrB), &dataB); err != nil {
		fmt.Errorf("invalid JSON in second argument: %v", err)
		return false
	}
	return reflect.DeepEqual(dataA, dataB)
}
func ByteToJSON(data []byte) (string, error) {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return "", fmt.Errorf("invalid JSON: %v", err)
	}
	compact, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to encode JSON: %v", err)
	}
	return strings.TrimSpace(string(compact)), nil
}

func Base64ToJSONString(base64Str string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(base64Str))
	if err != nil {
		return "", fmt.Errorf("invalid Base64: %v", err)
	}

	var v interface{}
	if err := json.Unmarshal(bytes, &v); err != nil {
		return "", fmt.Errorf("invalid JSON: %v", err)
	}
	compact, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to encode JSON: %v", err)
	}
	return string(compact), nil
}

func GetApplication(a *Traefikapim, headers http.Header, ddata []byte) []Application {

	appsRes := make([]Application, 0)

	apps := a.cfg.Applications

	fmt.Printf("Apps length : %v", len(apps))

	if len(apps) != 0 {
		if headers.Get(AuthorizationHeader) != "" && strings.HasPrefix(strings.ToLower(headers.Get(AuthorizationHeader)), strings.ToLower(BearerPrefix)) {
			token := strings.TrimPrefix(headers.Get(AuthorizationHeader), BearerPrefix)

			tokenType, err := GetFieldFromJWT(token, TokenType)
			if err != nil {
				fmt.Printf("Error while getting token type from token %s, %v", token, err)
			} else {
				if tokenType == JwtTokenRequestor {
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

		} else if strings.HasPrefix(strings.ToLower(headers.Get(AuthorizationHeader)), strings.ToLower(BasicPrefix)) {
			token := strings.TrimPrefix(headers.Get(AuthorizationHeader), BasicPrefix)
			user, pass, errBasic := ParseBasicAuth(token)
			fmt.Printf("Auth Type: Basic Auth %s %s, %s", token, user, MaskPassword(pass))

			if errBasic == nil {
				appsRes = FindApplicationyByBasicAuthType(a, apps, token)
			} else {
				fmt.Printf("No found app in config for this Basic Token %s, %v", token, errBasic)
			}

		} else if headers.Get(a.cfg.Global.SecureHeaderName) != "" {
			appsRes = FindApplicationyByStaticAuthType(a, apps, headers.Get(a.cfg.Global.SecureHeaderName))
		} else {

			fmt.Printf("NoAuth was specified")
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

func checkOauth2(u *Application, rw http.ResponseWriter, authHeader string) error {
	var publicKey *rsa.PublicKey
	var err error
	if u.JwtJks != "" {
		publicKey, err = getPublicKey(u.JwtJks)
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
					fmt.Println("Not Authorized: Error validating JWT : ", err)
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

func ReturnJwtToken(rw http.ResponseWriter, token string) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusAccepted)
	json.NewEncoder(rw).Encode(map[string]interface{}{
		"access_token": token,
	})
	return
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

func getBodyRequestJsonPathResult(path string, data interface{}) (interface{}, error) {

	fmt.Printf("pathpathpathpath %s", path)
	if path == "" || data == nil {
		return "", nil
	}

	steps, err := parseJsonPath(path)

	if err != nil {
		fmt.Println("Error parsing path:", err)
		return nil, err
	}

	result, err := evaluate(data, steps)

	if err != nil {
		fmt.Println("Error evaluating path:", err)
		return nil, err
	}
	return result, nil
}

func processJSON(data interface{}, dataJSON string, headers http.Header, queries url.Values) interface{} {
	var result interface{}

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

func getValFromQuery(v string, ddata []byte, headers http.Header, queries url.Values) interface{} {

	fmt.Print("vvvvvvvvvvvXXXXXvvvvvvv,%s", v)

	if len(ddata) > 0 {

		dataJSON := string(ddata)
		var template2 map[string]interface{}
		if err := json.Unmarshal([]byte(dataJSON), &template2); err != nil {
			panic(err)
		}

		if strings.HasPrefix(v, "$.") {
			result, _ := getBodyRequestJsonPathResult(v, template2)
			return result
		}
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
	return nil
}

func reconstructURI(path string, paramList []string) string {
	if len(paramList) == 0 {
		return path
	}

	queryString := strings.Join(paramList, "&")

	return fmt.Sprintf("%s?%s", path, queryString)
}

func updateNativeRequestUrl(uriString string, ddata []byte, headers http.Header, queries url.Values) string {

	u, err := url.Parse(uriString)
	if err != nil {
		fmt.Println("Error parsing URI:", err)
		return uriString
	}

	queryParams := u.Query()

	if len(queryParams) > 0 {
		var paramList []string
		for key, values := range queryParams {
			for _, value := range values {
				paramList = append(paramList, fmt.Sprintf("%s=%v", key, getValFromQuery(value, ddata, headers, queries)))
			}
		}

		return reconstructURI(u.Path, paramList)

	} else {
		return uriString
	}

}

func updateNativeRequestUrl2(uriString string, ddata []byte, headers http.Header, queries url.Values) string {
	var result = uriString
	var pathWithoutQueries = strings.Split(result, "?")

	for _, part := range strings.Split(pathWithoutQueries[0], "/") {
		fmt.Printf("resultresultresultresult %s", result)
		if strings.Contains(part, "$.") || strings.Contains(part, "_$c.") || strings.Contains(part, "_$h.") || strings.Contains(part, "_$q.") {
			result = strings.ReplaceAll(result, part, fmt.Sprintf("%v", getValFromQuery(part, ddata, headers, queries)))
		}
	}

	if len(pathWithoutQueries) > 1 {
		result = updateNativeRequestUrl(result, ddata, headers, queries)
	}
	fmt.Printf("URITRANS %s", result)
	return result

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
	fmt.Println("url: %s, client: %s, secret: %s", serverURL, clientID, secret)
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
		fmt.Printf("Error while getting access token using Global Configuration: %v\n", err)
		return ""
	}
	return "Bearer " + token.AccessToken
}

func (c *Application) GetTokenByApp(clientId string, secret string) string {
	client := NewOAuth2Client(
		c.UrlToken,
		clientId,
		secret,
	)

	token, err := client.GetAccessToken()
	if err != nil {
		fmt.Printf("Error while getting access token using Application configuration using %s %s: %v\n", err, clientId, secret)
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

	bodyBytes, err := io.ReadAll(req.Body)
	apps := GetApplication(a, req.Header, bodyBytes)
	var app *Application
	path := req.URL.Path
	method := req.Method
	var headers http.Header
	var queries url.Values

	headers = req.Header
	queries = req.URL.Query()

	if err != nil {
		http.Error(rw, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer req.Body.Close()

	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	toto := io.NopCloser(bytes.NewReader(bodyBytes))
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
						err := checkOauth2(app, rw, req.Header.Get(AuthorizationHeader))
						if err != nil {
							fmt.Printf("Auth Error : %v", err)
							ShowNoAuthError(rw)
							return
						}
					} else if app.SecurityType == Static {

						if app.SecureHeaderValue != req.Header.Get(a.cfg.Global.SecureHeaderName) {
							ShowNoAuthError(rw)
							return
						} else {
							fmt.Printf("Connected as Static")
						}

					} else if app.SecurityType == Basic {
						token := strings.TrimPrefix(headers.Get(AuthorizationHeader), BasicPrefix)
						if app.BaseBasicToken != token {
							ShowNoAuthError(rw)
							return
						} else {
							fmt.Printf("Connected as Basic Bearer")
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
		app = FindApplicationyApiAccessKey(apps, req.Header.Get(a.cfg.Global.SecureHeaderName))
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
		appOauth2Token := getTokenApp(a.cfg.Applications, "Oauth2EpToken")
		appJwtToken := getTokenApp(a.cfg.Applications, "JwtEpToken")

		if appJwtToken != nil && headers.Get(XGatewayApiKey) != "" && GetUrlInfo(appJwtToken, path, method) != nil {
			app = appJwtToken
			fmt.Println("is JWT api url")
			var bodyInJson map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &bodyInJson); err != nil {
				panic(err)
			}

			clientID, ok := bodyInJson["claimsSet"].(map[string]interface{})["client"].(string)
			if !ok {
				fmt.Println("Error: 'client' is not a string or not found")
				ShowNoAuthError(rw)
				return
			}

			token := appJwtToken.GetTokenByApp(clientID, headers.Get(XGatewayApiKey))

			if token == "" {
				ShowNoAuthError(rw)
				return
			}

			ReturnJwtToken(rw, strings.Replace(token, "Bearer ", "", 1))
			return
			//&& GetUrlInfo(appOauth2Token, path, method) != nil
		} else if appOauth2Token != nil && GetUrlInfo(appOauth2Token, path, method) != nil {
			app = appOauth2Token
			fmt.Printf("is Oauth2 api url, path: %s, method: %s", path, method)

			// Parse the form data
			if err := req.ParseForm(); err != nil {
				fmt.Printf("Failed to parse form when getting oauth2 token")
				return
			}

			// Retrieve specific fields
			clientID := req.Form.Get("client_id")
			clientSecret := req.Form.Get("client_secret")

			client := NewOAuth2Client(
				appOauth2Token.UrlToken,
				clientID,
				clientSecret,
			)

			token, err := client.GetAccessToken()

			if err != nil {
				ShowNoAppError(rw)
				fmt.Printf("Failed to get oauth2 token")
				return
			}

			if token == nil || token.AccessToken == "" {
				ShowNoAuthError(rw)
				return
			}

			ReturnJwtToken(rw, token.AccessToken)

			return
		} else {
			fmt.Printf("WALOOOOOOO")
		}

	}

	//Stage 2 : Whitelist

	if app != nil && app.AllowedIps != "" {

		if !isRequestWhitelisted(req, app.AllowedIps) {
			ShowForbiddenNotAllowedIPError(rw)
			return
		}

	}

	if app != nil {
		//Stage 2 : Transformations
		urlInfo := GetUrlInfo(app, path, method)
		fmt.Printf("Check Path UrlInfo  for app %s", app.Id)

		if urlInfo != nil {
			fmt.Printf("Path UrlInfo is found for %s %s, for app %s", method, path, app.Id)
			changeRequestHeaders(*urlInfo, req, bodyBytes, headers)

			if app.SendOauth2AuthHeader {
				req.Header.Set("Authorization", getToken(a))
			}

			if urlInfo.JsPathVarable != "" {
				newPath := updateNativeRequestUrl2(urlInfo.JsPathVarable, bodyBytes, headers, queries)
				modifiedURL := *req.URL
				modifiedURL.RawQuery = ""
				modifiedURL.Path = newPath
				path = newPath

				newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, modifiedURL.String(), toto)
				newReq.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				newReq.Header = req.Header.Clone()
				req = newReq

				req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

				contentLength := len(bodyBytes)
				req.ContentLength = int64(contentLength)
				req.Header.Set("Content-Length", strconv.Itoa(contentLength))
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
	} else {
		fmt.Printf("No app found")
	}

	fmt.Printf("Final Request URT Past %v,%v", req.URL, path)

	newURL := *req.URL  // Copy the original URL
	newBody := req.Body // Copy the original URL

	newURL.Path = path

	newURL.RawPath = path

	req.URL = &newURL
	req.Body = newBody

	req.RequestURI = req.URL.RequestURI()

	fmt.Printf("Final Request URT Past %v,%s", req.URL, path)
	a.next.ServeHTTP(rw, req)

}
