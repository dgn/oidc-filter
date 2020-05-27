use log::trace;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
// use std::time::Duration;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(OIDCFilter) });
}

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
}

impl HttpContext for OIDCFilter {
    fn on_http_request_headers(&mut self, _: usize) -> Action {
        trace!("Request");
        if !self.is_authorized() {
            trace!("Not authorized");
            let token = self.get_cookie("oidcToken");
            if token != "" {
                self.set_http_request_header("Authorization", Some(&format!("Bearer {}", token)));
                return Action::Continue
            }
            self.send_http_response(
                403,
                vec![("Powered-By", "proxy-wasm")],
                Some(b"Access forbidden.\n"),
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
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            if !body.is_empty() && body[0] % 2 == 0 {
                trace!("Access granted.");
                self.resume_http_request();
                return;
            }
        }
        trace!("Access forbidden.");
        self.send_http_response(
            403,
            vec![("Powered-By", "proxy-wasm")],
            Some(b"Access forbidden.\n"),
        );
    }
}
