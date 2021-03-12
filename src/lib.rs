use std::time::Duration;
use std::error::Error;
use log::{debug, error};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use url::form_urlencoded;
use serde::{Deserialize, Serialize};
const MAX: usize = usize::MAX;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(OIDCRootContext{
            config: FilterConfig{
                target_header_name: "".to_string(),
                cookie_name: "".to_string(),
                auth_cluster: "".to_string(),
                auth_host: "".to_string(),
                login_uri: "".to_string(),
                token_uri: "".to_string(),
                client_id: "".to_string(),
                client_secret: "".to_string(),
            }
        })
    });
}

struct OIDCFilter{
    config: FilterConfig
}

struct OIDCRootContext {
    config: FilterConfig
}

#[derive(Deserialize)]
struct FilterConfig {
    #[serde(default = "default_target_header_name")]
    target_header_name: String,
    #[serde(default = "default_oidc_cookie_name")]
    cookie_name: String,
    auth_cluster: String,
    auth_host: String,
    login_uri: String,
    token_uri: String,
    client_id: String,
    client_secret: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
    #[serde(default)]
    id_token: String,
    #[serde(default)]
    expires_in: i64
}

#[derive(Serialize, Deserialize)]
struct Claims {
    nonce: String,
    iss: String,
    proto: String,
    path: String,
    redirect_uri: String
}

fn default_oidc_cookie_name() -> String {
    "oidcToken".to_owned()
}

fn default_target_header_name() -> String {
    "authorization".to_owned()
}

impl OIDCFilter {
    fn get_header(&self, name: &str) -> String {
        let headers = self.get_http_request_headers();
        for (key,_value) in headers.iter() {
            if key.to_lowercase().trim() == name {
                return _value.to_owned();
            }
        }
        return "".to_owned();
    }

    fn get_code(&self) -> String {
        let path = self.get_http_request_header(":path").unwrap();
        let query_offset = path.find("?").unwrap_or(0) + 1;
        if query_offset == 1 { return "".to_owned(); }

        let query = &path[query_offset..path.len()];
        let encoded = form_urlencoded::parse(query.as_bytes());
        for (k, v) in encoded {
            if k == "code" {
                return v.to_owned().to_string();
            }
        }
        return "".to_owned();
    }

    fn get_cookie(&self, name: &str) -> String {
        let headers = self.get_http_request_headers();
        for (key,value) in headers.iter() {
            if key.to_lowercase().trim() == "cookie" {
                let cookies: Vec<_> = value.split(";").collect();
                for cookie_string in cookies {
                    let cookie_name_end = cookie_string.find('=').unwrap_or(0);
                    let cookie_name = &cookie_string[0..cookie_name_end];
                    if cookie_name.trim() == name {
                        return cookie_string[(cookie_name_end + 1)..cookie_string.len()].to_owned();
                    }
                }
            }
        }
        return "".to_owned()
    }

    fn get_callback_url(&self, host: &str, redirect_path: &str) -> String {
        let proto = self.get_proto();
        format!("{}://{}{}", proto, host, redirect_path)
    }

    fn get_authorization_url(&self, claims: Claims) -> String {
        let encoded: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", self.config.client_id.as_str())
            .append_pair("response_type", "code")
            .append_pair("scope", "openid profile email")
            .append_pair("redirect_uri", claims.redirect_uri.as_str())
            .append_pair("nonce", claims.nonce.as_str())
            .finish();

        format!("{}?{}", self.config.login_uri, encoded)
    }

    fn send_error(&self, code: u32, error: String) {
        error!("{}", error.as_str());
        self.send_http_response(
            code,
            vec![("Content-Type", "text/plain")],
            Some(error.as_bytes()),
        );
    }

    fn get_proto(&self) -> String {
        let proto = self.get_header("x-forwarded-proto");
        if proto != "" { return proto }
        return "http".to_owned()
    }

    fn to_set_cookie_header(&self, t: TokenResponse) -> String {
        let flags = if self.get_proto().as_str() == "http" { "HttpOnly" } else { "HttpOnly; Secure" };
        return format!("{}={};Max-Age={};{}", self.config.cookie_name, t.id_token, t.expires_in, flags)
    }

    fn to_del_cookie_header(&self, name: String) -> String {
        return format!("{}=;Max-Age=0", name.as_str());
    }

    fn create_handshake_object(&self) -> Result<(Claims, String), Box<dyn Error>> {
        let authority = self.get_http_request_header(":authority").unwrap();
        let path = self.get_http_request_header(":path").unwrap();
        let nonce = self.get_header("x-request-id");
        let claims = Claims{
            nonce: nonce,
            iss: authority.to_owned(),
            path: path.to_owned(),
            proto: self.get_proto(),
            redirect_uri: self.get_callback_url(&iss, &path)
        };

        let json = serde_json::to_string(&claims)?;
        let flags = if claims.proto.as_str() == "http" { "HttpOnly" } else { "HttpOnly; Secure" };
        let cookie_header = format!("{}.handshake={};Max-Age=300;{}", self.config.cookie_name, json.as_str(), flags);
        Ok((claims, cookie_header))
    }

    fn get_handshake_object(&self) -> Result<Claims, Box<dyn Error>> {
        let json = self.get_cookie(format!("{}.handshake", self.config.cookie_name.as_str()).as_str());
        let claims: Claims = serde_json::from_str(json.as_str()).unwrap();
        Ok(claims)
    }
}

impl HttpContext for OIDCFilter {

    fn on_http_request_headers(&mut self, _: usize) -> Action {
        // If the requester directly passes a header, this filter just passes the request
        // and the next filter should verify that the token is actually valid
        if self.get_header(self.config.target_header_name.as_str()) != "" {
            return Action::Continue
        }

        let token = self.get_cookie(self.config.cookie_name.as_str());
        if token != "" {
            debug!("Cookie found, setting auth header");
            self.set_http_request_header(self.config.target_header_name.as_str(), Some(&format!("Bearer {}", token)));
            return Action::Continue
        }

        // Non html requests don't need redirects
        let has_html_accept = self.get_header("accept").find("text/html").unwrap_or(MAX);
        if has_html_accept == MAX {
            self.send_error(403, "Not Authorized".to_owned());
            return Action::Pause
        }

        let code = self.get_code();
        if code != "" {
            let handshake = self.get_handshake_object().unwrap();
            debug!("Code found. Dispatching HTTP call to token endpoint");
            let data: String = form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "authorization_code")
                .append_pair("code", code.as_str())
                .append_pair("redirect_uri", handshake.redirect_uri.as_str())
                .append_pair("client_id", self.config.client_id.as_str())
                .append_pair("client_secret", self.config.client_secret.as_str())
                .append_pair("nonce", handshake.nonce.as_str())
                .finish();

            debug!("Sending data to token endpoint: {}", data);
            let token_request = self.dispatch_http_call(
                self.config.auth_cluster.as_str(),
                vec![
                    (":method", "POST"),
                    (":path", self.config.token_uri.as_str()),
                    (":authority", self.config.auth_host.as_str()),
                    ("Content-Type", "application/x-www-form-urlencoded"),
                ],
                Some(data.as_bytes()),
                vec![],
                Duration::from_secs(5)
            );

            match token_request {
                Err(e) => {
                    self.send_error(503, format!("Cannot dispatch call to cluster:  {:?}", e));
                }
                Ok(_) => {}
            }

            return Action::Pause
        }

        let handshake = self.create_handshake_object().unwrap();
        debug!("No code found. Redirecting to authorization endpoint {}", handshake.0.redirect_uri);
        self.send_http_response(
            302,
            vec![
                ("Set-Cookie", handshake.1.as_str()),
                ("Location", self.get_authorization_url(handshake.0).as_str())
            ],
            Some(b"")
        );

        return Action::Pause
    }
}

impl Context for OIDCFilter {

    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        debug!("Got response from token endpoint");
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            match serde_json::from_slice::<TokenResponse>(body.as_slice()) {
                Ok(data) => {
                    if data.error != "" {
                        let error = format!("error: {}, error_description: {}", data.error, data.error_description);
                        self.send_error(500, error);
                        return
                    }

                    if data.id_token != "" {
                        debug!("id_token found. Setting cookie and redirecting...");

                        let handshake = self.get_handshake_object().unwrap();
                        let source_url = format!("{}://{}{}", handshake.proto, handshake.iss, handshake.path);
                        self.send_http_response(
                            302,
                            vec![
                                ("Set-Cookie", self.to_set_cookie_header(data).as_str()),
                                ("Set-Cookie", self.to_del_cookie_header(format!("{}.handshake", self.config.cookie_name.as_str())).as_str()),
                                ("Location", source_url.as_str()),
                            ],
                            Some(b""),
                        );
                        return
                    }
                },
                Err(e) => {
                    self.send_error(500, format!("Invalid token response:  {:?}", e));
                }
            };
        } else {
            let error = format!("Received invalid payload from authorization server");
            self.send_error(500, error);
        }
    }
}

impl Context for OIDCRootContext {}

impl RootContext for OIDCRootContext {

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        if let Some(config_bytes) = self.get_configuration() {
            let cfg: FilterConfig = serde_json::from_slice(config_bytes.as_slice()).unwrap();
            self.config = cfg;
            true
        } else {
            error!("NO CONFIG PRESENT");
            false
        }
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(OIDCFilter{
            config: FilterConfig{
                target_header_name: self.config.target_header_name.clone(),
                cookie_name: self.config.cookie_name.clone(),
                auth_cluster: self.config.auth_cluster.clone(),
                auth_host: self.config.auth_host.clone(),
                login_uri: self.config.login_uri.clone(),
                token_uri: self.config.token_uri.clone(),
                client_id: self.config.client_id.clone(),
                client_secret: self.config.client_secret.clone(),
            },
        }))

    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}
