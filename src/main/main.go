package main

import (
	"strings"

	"github.com/mathetake/proxy-wasm-go/runtime"
)

var (
	rootContext = &oidcRootContext{}
	config      = &Config{}
	jsBody      = `
<html>
	<script>
		var uriHash = new URLSearchParams(
			window.location.hash.substr(1) // skip the first char (#)
		);
		var token = uriHash.get('access_token');
		if (token == null) {
			token = "";
		}
		document.cookie = "oidcToken=" + token;
		window.location.reload(true);
	</script>
</html>
`
)

func main() {
	runtime.SetNewRootContext(newRootContext)
	runtime.SetNewHttpContext(newContext)
}

type Config struct {
	Host          string
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

func parseConfig(config string) *Config {
	ret := &Config{}
	for _, line := range strings.Split(config, "\n") {
		configVal := strings.SplitN(line, ":", 2)
		if len(configVal) < 2 {
			continue
		}
		key := trim(configVal[0])
		value := trim(configVal[1])
		switch key {
		case "host":
			ret.Host = value
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
	runtime.LogDebug("Loading config")
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
	sendJSBody            bool
}

func (ctx *oidcFilter) getCookie(name string) string {
	cookieHeader, ok := ctx.GetHttpRequestHeader("cookie")
	if ok != runtime.StatusOk {
		return ""
	}

	for _, cookie := range strings.Split(cookieHeader, ";") {
		cookieParts := strings.Split(cookie, "=")
		if trim(cookieParts[0]) == name {
			return trim(cookieParts[1])
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
	host, ok := ctx.GetHttpRequestHeader("Host")
	if ok != runtime.StatusOk || host == "" {
		host = config.Host
	}
	path, ok := ctx.GetHttpRequestHeader(":path")
	if ok != runtime.StatusOk || path == "" {
		path = "/"
	}
	return getAuthURI(config.AuthBaseURI, config.Scope, config.ClientID, config.Scheme, host, path)
}

// override
func (ctx *oidcFilter) OnHttpRequestHeaders(_ int) runtime.Action {
	state := ctx.getCookie("oidcState")
	if state == "redirected" {
		runtime.LogDebug("Returning JS body to retrieve access_token")
		ctx.RememberHttpResponseHeader("set-cookie", "oidcState=")
		ctx.RememberHttpResponseHeader("Content-Type", "text/html; charset=UTF-8")
		ctx.SendHttpResponse(200, nil, jsBody)
		return runtime.ActionPause
	}
	token := ctx.getCookie("oidcToken")
	if token == "" {
		runtime.LogDebug("Redirecting")
		ctx.RememberHttpResponseHeader("set-cookie", "oidcState=redirected")
		ctx.RememberHttpResponseHeader("location", ctx.GetAuthURI())
		ctx.SendHttpResponse(302, nil, "")
		return runtime.ActionPause
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
	// if we got a 403 or 401, remove the cookie and refresh
	if ctx.requestIsUnauthorized() {
		ctx.RememberHttpResponseHeader("Content-Type", "text/html; charset=UTF-8")
		ctx.SendHttpResponse(200, nil, jsBody)
		return runtime.ActionPause
	}
	return runtime.ActionContinue
}
