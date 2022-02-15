use crate::constants;
use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct FilterConfig {
    #[serde(default = "constants::default_redirect_uri")]
    pub redirect_uri: String,
    #[serde(default = "constants::default_target_header_name")]
    pub target_header_name: String,
    #[serde(default = "constants::default_oidc_cookie_name")]
    pub cookie_name: String,
    pub auth_cluster: String,
    pub auth_host: String,
    pub login_uri: String,
    pub token_uri: String,
    pub client_id: String,
    pub client_secret: String,
}

impl FilterConfig {
    pub fn default() -> FilterConfig {
        FilterConfig {
            redirect_uri: "".to_string(),
            target_header_name: "".to_string(),
            cookie_name: "".to_string(),
            auth_cluster: "".to_string(),
            auth_host: "".to_string(),
            login_uri: "".to_string(),
            token_uri: "".to_string(),
            client_id: "".to_string(),
            client_secret: "".to_string(),
        }
    }
}
