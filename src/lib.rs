use log::trace;
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

const AUTH_CLUSTER: &str = "keycloak.default.svc.cluster.local";
const AUTH_URI: &str = "http://localhost:9090/auth/realms/master/protocol/openid-connect/auth";

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
        return "".to_string()
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
            .append_pair("response_type", "code")
            .append_pair("scope", "openid profile email")
            .append_pair("redirect_uri", current_uri)
            .finish();
        
        format!("{}?{:?}", AUTH_URI, encoded)
    }
}

impl HttpContext for OIDCFilter {
    fn on_http_request_headers(&mut self, _: usize) -> Action {
        let path = self.get_http_request_header(":path").unwrap();
        trace!("Request");
        if !self.is_authorized() {
            trace!("Not authorized");
            let token = self.get_cookie("oidcToken");
            if token != "" {
                self.set_http_request_header("Authorization", Some(&format!("Bearer {}", token)));
                return Action::Continue
            }

            let code = self.get_code();
            if code != "" {
                let _ = self.dispatch_http_call(AUTH_CLUSTER, vec![], Some(b""), vec![], Duration::new(5, 0));
                return Action::Pause
            }

            self.send_http_response(
                302,
                vec![("Location", self.get_redirect_uri(path.as_str()).as_str())],
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
        let path = self.get_http_request_header(":path").unwrap();
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            let data: Value = serde_json::from_slice(body.as_slice()).unwrap();

            if data["id_token"] != "" {
                self.send_http_response(
                    302,
                    vec![
                        ("SetCookie", format!("oidcToken={}", data["id_token"]).as_str()),
                        ("Location", path.as_str()),
                    ],
                    Some(b""),
                );
            }
        }
        trace!("Access forbidden.");
    }
}
