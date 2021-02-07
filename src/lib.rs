use log::{debug, error};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use url::form_urlencoded;
use std::time::Duration;
use serde::{Deserialize};

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
    authority: String,
    path: String,
    config: FilterConfig,
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

fn default_oidc_cookie_name() -> String {
    "oidcToken".to_string()
}

fn default_target_header_name() -> String {
    "authorization".to_string()
}

impl OIDCFilter {
    fn is_authorized(&self) -> bool {
        let headers = self.get_http_request_headers();
        for (key,_value) in headers.iter() {
            if key.to_lowercase().trim() == "authorization" {
                return true;
            }
        }
        return false;
    }

    fn get_code(&self) -> String {
        let path = self.get_http_request_header(":path").unwrap();
        let path_parts: Vec<_> = path.split("?").collect();
        if path_parts.len() < 2 {
            return "".to_string()
        }
        let query = path_parts[1].to_string();
        let encoded = form_urlencoded::parse(query.as_bytes());
        for (k, v) in encoded {
            if k == "code" {
                return v.to_owned().to_string();
            }
        }
        return "".to_string();
    }

    fn get_cookie(&self, name: &str) -> String {
        let headers = self.get_http_request_headers();
        for (key,value) in headers.iter() {
            if key.to_lowercase().trim() == "cookie" {
                let assignments: Vec<_> = value.split(";").collect();
                for assignment in assignments {
                    let kvpair: Vec<_> = assignment.split("=").collect();
                    if kvpair[0].trim() == name {
                        return kvpair[1].to_owned();
                    }
                }
            }
        }
        return "".to_owned()
    }

    fn get_callback_url(&self, host: &str, redirect_path: &str) -> String {
        let headers = self.get_http_request_headers();
        for (key,_value) in headers.iter() {
            if key.to_lowercase().trim() == "x-forwarded-proto" {
                return format!("{}://{}{}", _value, host, redirect_path);
            }
        }

        format!("http://{}{}", host, redirect_path)
    }

    fn get_authorization_url(&self, current_uri: &str) -> String {
        let encoded: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", self.config.client_id.as_str())
            .append_pair("response_type", "code")
            .append_pair("scope", "openid profile email")
            .append_pair("redirect_uri", current_uri)
            .finish();

        format!("{}?{}", self.config.login_uri, encoded)
    }

    fn get_http_authority(&self) -> String {
        return self.authority.to_owned();
    }

    fn set_http_authority(&mut self, authority: String) {
        self.authority = authority.to_owned();
    }

    fn get_http_path(&self) -> String {
        return self.path.to_owned();
    }

    fn set_http_path(&mut self, path: String) {
        self.path = path.to_owned();
    }

    fn send_internal_server_error(&self, error: String) {
        error!("{}", error.as_str());
        self.send_http_response(
            500,
            vec![("Content-Type", "text/plain")],
            Some(error.as_bytes()),
        );
    }

    fn to_set_cookie_header(&self, t: TokenResponse) -> String {
        let headers = self.get_http_request_headers();
        let mut flags = "HttpOnly; Secure";
        for (key,_value) in headers.iter() {
            if key.to_lowercase().trim() == "x-forwarded-proto" {
                if _value == "http" {
                    flags = "HttpOnly";
                }
                break
            }
        }

        return format!("{}={};Max-Age={};{}", self.config.cookie_name, t.id_token, t.expires_in, flags)
    }
}

impl HttpContext for OIDCFilter {

    fn on_http_request_headers(&mut self, _: usize) -> Action {
        if self.is_authorized() {
            return Action::Continue
        }

        let token = self.get_cookie(self.config.cookie_name.as_str());
        if token != "" {
            debug!("Cookie found, setting auth header");
            self.set_http_request_header(self.config.target_header_name.as_str(), Some(&format!("Bearer {}", token)));
            return Action::Continue
        }

        let host = self.get_http_request_header(":authority").unwrap();
        let path = self.get_http_request_header(":path").unwrap();
        let path_parts: Vec<_> = path.split('?').collect();
        let redirect_path = path_parts[0];
        let callback_url = self.get_callback_url(&host, &redirect_path);

        let code = self.get_code();
        if code != "" {
            debug!("Code found. Dispatching HTTP call to token endpoint: {}", &callback_url);
            self.set_http_path(redirect_path.to_owned());
            self.set_http_authority(host.to_owned());

            let data: String = form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "authorization_code")
                .append_pair("code", code.as_str())
                .append_pair("redirect_uri", callback_url.as_str())
                .append_pair("client_id", self.config.client_id.as_str())
                .append_pair("client_secret", self.config.client_secret.as_str())
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
                    self.send_internal_server_error(format!("Cannot dispatch call to cluster:  {:?}", e));
                }
                Ok(_) => {}
            }

            return Action::Pause
        }

        debug!("No code found. Redirecting to authorization endpoint {}", &callback_url);
        self.send_http_response(
            302,
            vec![("Location", self.get_authorization_url(callback_url.as_str()).as_str())],
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
                        self.send_internal_server_error(error);
                        return
                    }

                    if data.id_token != "" {
                        debug!("id_token found. Setting cookie and redirecting...");

                        let host = self.get_http_authority();
                        let path = self.get_http_path();
                        self.send_http_response(
                            302,
                            vec![
                                ("Set-Cookie", self.to_set_cookie_header(data).as_str()),
                                // Replace this get_callback_url call with the source url
                                // We also need nonce support, so it's best to
                                // persist the origin host and url in a signed jwt
                                ("Location", self.get_callback_url(&host, &path).as_str()),
                            ],
                            Some(b""),
                        );
                        return
                    }
                },
                Err(e) => {
                    self.send_internal_server_error(format!("Invalid token response:  {:?}", e));
                }
            };
        } else {
            let error = format!("Invalid payload received");
            self.send_internal_server_error(error);
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
            authority: "".to_string(),
            path: "".to_string(),
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
