use std::collections::HashMap;

use http::header::AUTHORIZATION;
use rand::{rng, seq::IndexedRandom};
use serde_json::{json, Value};
use url::Url;
use wasm_bindgen::JsValue;
use worker::{console_log, wasm_bindgen, Request, RequestInit};

use crate::config::{Config, Identifier, Model, Provider, Rule};
use crate::error::Error;

const STREAM_FIELD: &'static str = "stream";
const MODEL_FIELD: &'static str = "model";

#[derive(Debug, Clone)]
pub struct Router {
    rules: HashMap<Model, Rule>,
    providers: HashMap<Identifier, Provider>,
}

impl Router {
    pub fn new(config: Config) -> Self {
        let mut rules = HashMap::new();
        for rule in config.rules {
            rules.insert(rule.model.clone(), rule.clone());
        }

        let mut providers = HashMap::new();
        for provider in config.providers {
            providers.insert(provider.identifier.clone(), provider.clone());
        }

        Self { rules, providers }
    }

    /// Routes the request according to the rules configured, and returns
    /// the new modified request and whether it is a stream request.
    pub async fn route(&self, req: Request) -> Result<(Request, bool), Error> {
        let mut original_req = req.clone()?;
        let request_body = original_req.json::<Value>().await?;
        // Retrieve some important information from the request body.
        let is_stream = request_body
            .get(STREAM_FIELD)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let model = request_body
            .get(MODEL_FIELD)
            .and_then(|v| v.as_str())
            .unwrap_or("gpt-4o");
        // Find the rule for this model.
        let rule = self.get_rule(model)?;
        // Randomly select a provider from the rule.
        let rule_provider = rule
            .providers
            .choose(&mut rng())
            .expect("no provider found");
        let target_model = rule_provider.model.clone();
        let provider = self.get_provider(&rule_provider.identifier)?;
        // Build the new request.
        let new_req = Self::build_request(req, provider, &target_model).await?;
        console_log!(
            "routing the {} request for model {} from {} to {}",
            if is_stream { "stream" } else { "non-stream" },
            model,
            original_req.url()?,
            new_req.url()?
        );

        Ok((new_req, is_stream))
    }

    async fn build_request(
        mut req: Request,
        provider: &Provider,
        target_model: &str,
    ) -> Result<Request, Error> {
        // Modify the target URL.
        let base_url =
            Url::parse(provider.endpoint.as_str()).expect("failed to parse provider endpoint");
        let new_url = base_url
            .join(provider.path.as_str())
            .expect("failed to join provider path");

        // Modify the headers.
        let mut headers = req.headers().clone();
        headers.set(
            AUTHORIZATION.as_str(),
            &format!("Bearer {}", provider.api_key,),
        )?;
        headers.delete("cf-connecting-ip")?;

        // Modify the request body.
        let mut body = req.json::<Value>().await?;
        if let Some(model_field) = body.get_mut(MODEL_FIELD) {
            *model_field = json!(target_model);
        } else {
            return Err(Error::MissingField(MODEL_FIELD.to_string()));
        }

        Ok(Request::new_with_init(
            new_url.as_str(),
            &RequestInit {
                method: req.method().clone(),
                headers,
                body: Some(JsValue::from(body.to_string())),
                ..Default::default()
            },
        )?)
    }

    fn get_rule(&self, model: &str) -> Result<&Rule, Error> {
        self.rules
            .get(model)
            .ok_or(Error::RuleNotFound(model.to_string()))
    }

    fn get_provider(&self, identifier: &Identifier) -> Result<&Provider, Error> {
        self.providers
            .get(identifier)
            .ok_or(Error::ProviderNotFound(identifier.to_string()))
    }
}
