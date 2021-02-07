use log::{debug, info};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use url::form_urlencoded;
use serde_json::{Value};
use std::time::Duration;


#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(OIDCRootContext{
            config: FilterConfig{
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

struct FilterConfig {
    auth_cluster: String,
    auth_host: String,
    login_uri: String,
    token_uri: String,
    client_id: String,
    client_secret: String,
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
        let mut cookies = "";
        for (key,value) in headers.iter() {
            if key.to_lowercase().trim() == "cookie" {
                cookies = value;
            }
        }
        let assignments: Vec<_> = cookies.split(";").collect();
        for assignment in assignments {
            let kvpair: Vec<_> = assignment.split("=").collect();
            if kvpair[0].trim() == name {
                return kvpair[1].to_owned();
            }
        }
        return "".to_owned()
    }

    fn get_redirect_uri(&self, current_uri: &str) -> String {
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

}

impl HttpContext for OIDCFilter {

    fn on_http_request_headers(&mut self, _: usize) -> Action {
        let host = self.get_http_request_header(":authority").unwrap();
        let path = self.get_http_request_header(":path").unwrap();
        self.set_http_authority(host.to_owned());

        // TODO: move this into its own fn filter_query
        let path_parts: Vec<_> = path.split("?").collect();
        let mut redirect_path_serializer: url::form_urlencoded::Serializer<String> = form_urlencoded::Serializer::new(String::new());
        let redirect_path: String;
        if path_parts.len() < 2 {
            redirect_path = path.clone();
        } else {
            for (key, value) in form_urlencoded::parse(path_parts[1].as_bytes()).into_owned() {
                if key != "code" && key != "session_state" {
                    redirect_path_serializer.append_pair(key.as_str(), value.as_str());
                }
            }
            let query: String = redirect_path_serializer.finish();
            if query == "" {
                redirect_path = path_parts[0].to_string();
            } else {
                redirect_path = format!("{}?{}", path_parts[0], query);
            }
        }
        self.set_http_path(redirect_path.to_owned());

        info!("Request received");
        if !self.is_authorized() {
            info!("No auth header present. Checking for cookie containing id_token");
            let token = self.get_cookie("oidcToken");
            if token != "" {
                info!("Cookie found, setting auth header");
                self.set_http_request_header("Authorization", Some(&format!("Bearer {}", token)));
                return Action::Continue
            }

            info!("No cookie found. Checking for code in request parameters");
            let code = self.get_code();
            if code != "" {
                info!("Code found. Dispatching HTTP call to token endpoint");
                let data: String = form_urlencoded::Serializer::new(String::new())
                    .append_pair("grant_type", "authorization_code")
                    .append_pair("code", code.as_str())
                    .append_pair("redirect_uri", format!("http://{}{}", host, redirect_path).as_str())
                    .append_pair("client_id", self.config.client_id.as_str())
                    .append_pair("client_secret", self.config.client_secret.as_str())
                    .finish();
                info!("Sending data to token endpoint: {}", data);

                self.dispatch_http_call(
                    self.config.auth_cluster.as_str(), vec![
                        (":method", "POST"),
                        (":path", self.config.token_uri.as_str()),
                        (":authority", self.config.auth_host.as_str()),
                        ("Content-Type", "application/x-www-form-urlencoded"),
                    ],
                    Some(data.as_bytes()),
                    vec![],
                    Duration::from_secs(5)
                ).unwrap();
                return Action::Pause
            }

            info!("No code found. Redirecting to auth endpoint");
            self.send_http_response(
                302,
                vec![("Location", self.get_redirect_uri(format!("http://{}{}", host, path).as_str()).as_str())],
                Some(b""),
            );
            return Action::Pause
        }
        Action::Continue
    }
}

impl Context for OIDCFilter {

    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        info!("Got response from token endpoint");
        let host = self.get_http_authority();
        let path = self.get_http_path();
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            let data: Value = serde_json::from_slice(body.as_slice()).unwrap();
            debug!("Received json blob: {}", data);
            if data.get("error") != None {
                info!("Error fetching token: {}, {}", data.get("error").unwrap(), data.get("error_description").unwrap());
                return
            }
            if data.get("id_token") != None {
                info!("id_token found. Setting cookie and redirecting...");
                self.send_http_response(
                    302,
                    vec![
                        ("Set-Cookie", format!("oidcToken={};Max-Age={}", data.get("id_token").unwrap(), data.get("expires_in").unwrap()).as_str()),
                        ("Location", format!("http://{}{}", host, path).as_str()),
                    ],
                    Some(b""),
                );
                return
            }
        }
    }
}

impl Context for OIDCRootContext {}

impl RootContext for OIDCRootContext {

    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        info!("VM STARTED");
        true
    }

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        info!("READING CONFIG");
        if self.config.auth_cluster == "" {
            info!("CONFIG EMPTY");
            if let Some(config_bytes) = self.get_configuration() {
                info!("GOT CONFIG");
                // TODO: some proper error handling here
                let cfg: Value = serde_json::from_slice(config_bytes.as_slice()).unwrap();
                self.config.auth_cluster = cfg.get("auth_cluster").unwrap().as_str().unwrap().to_string();
                self.config.auth_host = cfg.get("auth_host").unwrap().as_str().unwrap().to_string();
                self.config.login_uri = cfg.get("login_uri").unwrap().as_str().unwrap().to_string();
                self.config.token_uri = cfg.get("token_uri").unwrap().as_str().unwrap().to_string();
                self.config.client_id = cfg.get("client_id").unwrap().as_str().unwrap().to_string();
                self.config.client_secret = cfg.get("client_secret").unwrap().as_str().unwrap().to_string();
            }
        }
        true
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(OIDCFilter{
            authority: "".to_string(),
            path: "".to_string(),
            config: FilterConfig{
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
