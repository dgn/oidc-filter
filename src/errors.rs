use serde::Serialize;

#[derive(Serialize)]
pub struct ErrorResponse {
    status: String,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

impl ErrorResponse {
    pub fn new(error: String, description: Option<String>) -> ErrorResponse {
        ErrorResponse {
            status: "error".to_owned(),
            error: error,
            error_description: description,
        }
    }
}
