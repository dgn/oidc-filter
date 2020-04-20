package main

import (
	"strings"

	"github.com/mathetake/proxy-wasm-go/runtime"
)

var (
	rootContext = &oidcRootContext{}
	config      = &Config{}
)

func main() {
	runtime.SetNewRootContext(newRootContext)
	runtime.SetNewHttpContext(newContext)
}

type Config struct {
	Scope         string
	ClientID      string
	AuthBaseURI   string
	Scheme        string
	TokenLifetime string
}

type oidcRootContext struct {
	runtime.RootContext
}

func newRootContext(contextID uint32) runtime.RootContext {
	return &oidcRootContext{}
}

func newContext(contextID uint32) runtime.HttpContext {
	return &oidcFilter{contextID: contextID, cachedResponseHeaders: map[string]string{}}
}

func trim(input string) string {
	whitespaces := "\n\t "
	ret := ""
	index := 0
	// first loop: until first non-whitespace char
	for _, c := range input {
		index++
		ignore := strings.ContainsRune(whitespaces, c)
		if !ignore {
			ret += string(c)
			break
		}
	}
	if index == len(input) {
		return ret
	}
	copy := ret
	// second loop: until the end
	for _, c := range input[index:] {
		index++
		copy += string(c)
		ignore := strings.ContainsRune(whitespaces, c)
		// if non-ws rune is found, use the copy and start from scratch
		if !ignore {
			ret = copy
		}
	}
	return ret
}

func parseConfig(config string) *Config {
	ret := &Config{}
	for _, line := range strings.Split(config, "\n") {
		configVal := strings.SplitN(line, ":", 2)
		if len(configVal) < 2 {
			continue
		}
		runtime.LogError(line)
		key := trim(configVal[0])
		value := trim(configVal[1])
		runtime.LogError(key)
		runtime.LogError(value)

		switch key {
		case "auth_uri":
			ret.AuthBaseURI = value
		case "scheme":
			ret.Scheme = value
		case "client_id":
			ret.ClientID = value
		case "scope":
			ret.Scope = value
		default:
			continue
		}
	}
	return ret
}

// override
func (ctx *oidcRootContext) OnConfigure(_ int) bool {
	runtime.LogInfo("Loading config")
	configBytes, status := ctx.GetConfiguration()
	if status != runtime.StatusOk {
		return false
	}
	config = parseConfig(string(configBytes))
	return true
}

type oidcFilter struct {
	runtime.HttpContext

	contextID             uint32
	cachedResponseHeaders map[string]string
}

func (ctx *oidcFilter) getTokenFromCookie() string {
	cookieHeader, ok := ctx.GetHttpRequestHeader("cookie")
	if ok != runtime.StatusOk {
		return ""
	}

	for _, cookie := range strings.Split(cookieHeader, ";") {
		cookieParts := strings.Split(cookie, "=")
		if cookieParts[0] == "oidcToken" {
			return cookieParts[1]
		}
	}
	return ""

}

func (ctx *oidcFilter) getTokenFromPath() string {
	path, ok := ctx.GetHttpRequestHeader(":path")
	if ok != runtime.StatusOk {
		return ""
	}
	varStart := strings.Index(path, "?")
	if varStart < 0 {
		return ""
	}

	for _, variable := range strings.Split(path[varStart:], "&") {
		variableParts := strings.Split(variable, "=")
		if variableParts[0] == "access_token" {
			return variableParts[1]
		}
	}
	return ""
}

func getAuthURI(authURI, scope, clientID, scheme, requestHost, requestPath string) string {
	return authURI + "?scope=" + scope +
		"&response_type=id_token%20token&client_id=" + clientID +
		"&nonce=blah" +
		"&redirect_uri=" + scheme + "://" + requestHost + requestPath
}

func (ctx *oidcFilter) GetAuthURI() string {
	host, ok := ctx.GetHttpRequestHeader("host")
	if ok != runtime.StatusOk || host == "" {
		host = "localhost:18000"
	}
	path, ok := ctx.GetHttpRequestHeader(":path")
	if ok != runtime.StatusOk || path == "" {
		path = "/"
	}
	return getAuthURI(config.AuthBaseURI, config.Scope, config.ClientID, config.Scheme, host, path)
}

// override
func (ctx *oidcFilter) OnHttpRequestHeaders(_ int) runtime.Action {
	token := ctx.getTokenFromCookie()
	if token == "" {
		token = ctx.getTokenFromPath()
		if token == "" {
			ctx.RememberHttpResponseHeader("location", ctx.GetAuthURI())
			ctx.SendHttpResponse(302, nil, "")
			return runtime.ActionPause
		}
		ctx.RememberHttpResponseHeader("set-cookie", "oidcToken="+token)
	}

	ctx.SetHttpRequestHeader("authorization", "Bearer "+token)
	return runtime.ActionContinue
}

func (ctx *oidcFilter) RememberHttpResponseHeader(header, value string) {
	ctx.cachedResponseHeaders[header] = value
}

func (ctx *oidcFilter) requestIsUnauthorized() bool {
	statusCode, _ := ctx.GetHttpResponseHeader(":status")
	if statusCode == "401" || statusCode == "403" {
		return true
	}
	return false
}

// override
func (ctx *oidcFilter) OnHttpResponseHeaders(_ int) runtime.Action {
	// fill in whatever we have from request phase
	for key, value := range ctx.cachedResponseHeaders {
		ctx.SetHttpResponseHeader(key, value)
	}
	// if we got a 403 or 401, remove the cookie
	if ctx.requestIsUnauthorized() {
		ctx.SetHttpResponseHeader("set-cookie", "oidcToken=")
	}
	return runtime.ActionContinue
}
