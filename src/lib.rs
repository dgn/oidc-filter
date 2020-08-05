use log::{debug, info, warn};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use url::form_urlencoded;
use serde_json::{Value};
use std::time::Duration;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(OIDCFilter) });
}

const AUTH_CLUSTER: &str = "outbound|8080||keycloak.default.svc.cluster.local";
const AUTH_HOST: &str = "keycloak.default.svc.cluster.local:8080";
const AUTH_URI: &str = "http://localhost:9090/auth/realms/master/protocol/openid-connect/auth";
const TOKEN_URI: &str = "http://localhost:9090/auth/realms/master/protocol/openid-connect/token";

struct OIDCFilter;

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
            if kvpair[0] == name {
                return kvpair[1].to_owned();
            }
        }
        return "".to_owned()
    }

    fn get_redirect_uri(&self, current_uri: &str) -> String {
        let encoded: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", "test")
            .append_pair("response_type", "code")
            .append_pair("scope", "openid profile email")
            .append_pair("redirect_uri", current_uri)
            .finish();
        
        format!("{}?{}", AUTH_URI, encoded)
    }
}

impl HttpContext for OIDCFilter {
    fn on_http_request_headers(&mut self, _: usize) -> Action {
        let host = self.get_http_request_header(":authority").unwrap();
        let path = self.get_http_request_header(":path").unwrap();
        let path_parts: Vec<_> = path.split("?").collect();
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
                .append_pair("redirect_uri", format!("http://{}{}", host, path_parts[0]).as_str())
                .append_pair("client_id", "test")
                .append_pair("client_secret", "30b8c95d-2885-49e5-bfe2-3c0c5e603eff")
                .finish();
                debug!("Sending data to token endpoint: {}", data);
                
                self.dispatch_http_call(AUTH_CLUSTER, vec![
                    (":method", "POST"),
                    (":path", TOKEN_URI),
                    (":authority", AUTH_HOST),
                    ("Content-Type", "application/x-www-form-urlencoded"),
                ], Some(data.as_bytes()), vec![], Duration::from_secs(5)).unwrap();
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

    fn on_http_response_headers(&mut self, _: usize) -> Action {
        self.set_http_response_header("Powered-By", Some("proxy-wasm"));
        Action::Continue
    }
}

impl Context for OIDCFilter {
    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        info!("Got response from token endpoint");
        //let host = self.get_http_request_header(":authority").unwrap();
        //let path = self.get_http_request_header(":path").unwrap();
        let host = "localhost:8080";
        let path = "/";
        let path_parts: Vec<_> = path.split("?").collect();
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
                        ("Location", format!("http://{}{}", host, path_parts[0]).as_str()),
                    ],
                    Some(b""),
                );
                return
            }
        }
    }
}
