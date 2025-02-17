use wasm_bindgen::JsValue;
use worker::wasm_bindgen;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Yaml(#[from] serde_json::Error),

    #[error(transparent)]
    Worker(#[from] worker::Error),

    #[error(transparent)]
    Kv(#[from] worker_kv::KvError),

    #[error("no config found in KV")]
    NoConfigFoundInKV,

    #[error("provider {0} is invalid due to illegal identifier")]
    ProviderInvalidIdentifier(String),

    #[error("provider {0} is invalid due to empty endpoint")]
    ProviderInvalidEndpoint(String),

    #[error("provider {0} is invalid due to empty models")]
    ProviderInvalidModels(String),

    #[error("provider identifier {0} is not unique")]
    ProviderIdentifierNotUnique(String),

    #[error("rule model {0} is not unique")]
    RuleModelNotUnique(String),

    #[error("rule provider {0} not found")]
    RuleProviderNotFound(String),

    #[error("rule model {0} not found in provider {1}")]
    RuleModelNotFound(String, String),

    #[error("rule for model {0} not found")]
    RuleNotFound(String),

    #[error("provider {0} not found")]
    ProviderNotFound(String),

    #[error("missing field {0} in the request body")]
    MissingField(String),
}

impl From<Error> for worker::Error {
    fn from(e: Error) -> Self {
        worker::Error::Internal(JsValue::from_str(&e.to_string()))
    }
}
