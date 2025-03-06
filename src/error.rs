use http::header::CONTENT_TYPE;
use serde_json::json;
use worker::{Headers, Response};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Worker error: {0}")]
    Worker(#[from] worker::Error),

    #[error("KV error: {0}")]
    Kv(#[from] worker_kv::KvError),

    #[error("The API key in the request is missing or invalid.")]
    Unauthorized,

    #[error("No configuration found in KV.")]
    NoConfigFoundInKV,

    #[error("The provider {0} is invalid due to an illegal identifier.")]
    ProviderInvalidIdentifier(String),

    #[error("The provider {0} is invalid due to an empty endpoint.")]
    ProviderInvalidEndpoint(String),

    #[error("The provider {0} is invalid due to empty models.")]
    ProviderInvalidModels(String),

    #[error("The provider identifier {0} is not unique.")]
    ProviderIdentifierNotUnique(String),

    #[error("The rule model {0} is not unique.")]
    RuleModelNotUnique(String),

    #[error("The rule provider {0} was not found.")]
    RuleProviderNotFound(String),

    #[error("The rule model {0} was not found in the provider {1}.")]
    RuleModelNotFound(String, String),

    #[error("The rule for model {0} was not found.")]
    RuleNotFound(String),

    #[error("The provider {0} was not found.")]
    ProviderNotFound(String),

    #[error("The field {0} is missing in the request body.")]
    MissingField(String),
}

impl Error {
    pub fn to_response(&self) -> (serde_json::Value, u16) {
        let status = match self {
            Self::MissingField(_) => 400,
            Self::ProviderInvalidIdentifier(_) => 400,
            Self::ProviderInvalidEndpoint(_) => 400,
            Self::ProviderInvalidModels(_) => 400,
            Self::ProviderIdentifierNotUnique(_) => 400,
            Self::RuleModelNotUnique(_) => 400,
            Self::Json(_) => 400,
            Self::Unauthorized => 401,
            Self::NoConfigFoundInKV => 404,
            Self::ProviderNotFound(_) => 404,
            Self::RuleNotFound(_) => 404,
            Self::RuleProviderNotFound(_) => 404,
            Self::RuleModelNotFound(_, _) => 404,
            Self::Io(_) | Self::Worker(_) | Self::Kv(_) => 500, // Server errors
        };

        let error_type = match status {
            400 => "BadRequest",
            401 => "Unauthorized",
            404 => "NotFound",
            _ => "InternalServerError",
        };

        let json = json!({
            "error": {
                "code": format!("{:?}", self),
                "message": self.to_string(),
                "type": error_type
            }
        });

        (json, status)
    }
}

impl From<Error> for worker::Result<worker::Response> {
    fn from(e: Error) -> Self {
        let mut headers = Headers::new();
        headers
            .set(CONTENT_TYPE.as_str(), "application/json")
            .unwrap();
        let (json, status) = e.to_response();
        Ok(Response::error(json.to_string(), status)
            .unwrap()
            .with_headers(headers))
    }
}
