pub const DEFAULT_REDIRECT_URL: &str = "{proto}://{authority}{path}";
pub const DEFAULT_OIDC_COOKIE_NAME: &str = "oidcToken";
pub const DEFAULT_TARGET_HEADER_NAME: &str = "authorization";

pub fn default_redirect_uri() -> String {
    String::from(DEFAULT_REDIRECT_URL)
}

pub fn default_target_header_name() -> String {
    String::from(DEFAULT_TARGET_HEADER_NAME)
}

pub fn default_oidc_cookie_name() -> String {
    String::from(DEFAULT_OIDC_COOKIE_NAME)
}
