use std::collections::HashMap;
use std::sync::Arc;

use async_std::sync::RwLock;
use http::header::AUTHORIZATION;
use rand::Rng;
use rand::{rng, seq::IndexedRandom};
use serde_json::{json, Value};
use url::Url;
use wasm_bindgen::JsValue;
use worker::{console_log, wasm_bindgen, Date, Fetch, Request, RequestInit, Response};

use crate::config::{Config, Identifier, Model, Provider, Rule, RuleProvider};
use crate::error::Error;

const STREAM_FIELD: &str = "stream";
const MODEL_FIELD: &str = "model";
const FALLBACK_MODEL: &str = "gpt-4o";
const RANDOM_PROVIDER_CHANCE: f64 = 0.2;

#[derive(Debug)]
pub struct Router {
    rules: HashMap<Model, Rule>,
    providers: HashMap<Identifier, Provider>,
    // The latency of each provider in milliseconds.
    latency: RwLock<HashMap<(Identifier, Model), u64>>,
}

impl Router {
    pub fn new(config: Config) -> Arc<Self> {
        let mut rules = HashMap::new();
        for rule in config.rules {
            rules.insert(rule.model.clone(), rule.clone());
        }

        let mut providers = HashMap::new();
        for provider in config.providers {
            providers.insert(provider.identifier.clone(), provider.clone());
        }

        Arc::new(Self {
            rules,
            providers,
            latency: RwLock::new(HashMap::new()),
        })
    }

    async fn update_latency(&self, identifier: &Identifier, model: &Model, latency: u64) {
        let mut latency_guard = self.latency.write().await;
        latency_guard.insert((identifier.clone(), model.clone()), latency);
    }

    /// Routes the request according to the rules configured, and returns
    /// the new modified request and whether it is a stream request.
    pub async fn route(&self, req: Request) -> Result<Response, Error> {
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
            .unwrap_or(FALLBACK_MODEL)
            .to_string();

        // Find the rule for this model.
        let rule = self.get_rule(&model)?;
        // Pick up a provider from the rule providers.
        let picked_rule_provider = self.pick_provider(rule).await?;
        // Get the mapped target model from the provider.
        let target_model = picked_rule_provider.model.clone();
        // Get the provider through the identifier.
        let provider = self.get_provider(&picked_rule_provider.identifier)?;

        // Build the new request and send it to the provider endpoint.
        let new_req = Self::build_request(req, provider, &target_model).await?;
        let (original_url, routed_url) = (original_req.url()?, new_req.url()?);
        console_log!(
            "routing the {} request for model {} from {} to {}",
            if is_stream { "stream" } else { "non-stream" },
            model,
            original_url,
            routed_url
        );
        let start = Date::now().as_millis();
        let resp = Fetch::Request(new_req).send().await?;
        let duration = Date::now().as_millis() - start;
        console_log!(
            "finished routing the {} request for model {} from {} to {} with status {} in {}ms",
            if is_stream { "stream" } else { "non-stream" },
            model,
            original_url,
            routed_url,
            resp.status_code(),
            duration
        );
        self.update_latency(
            &provider.identifier,
            &model,
            if resp.status_code() == 200 {
                duration
            } else {
                u64::MAX
            },
        )
        .await;

        Ok(resp)
    }

    /// Picks a provider from the rule.
    async fn pick_provider(&self, rule: &Rule) -> Result<RuleProvider, Error> {
        let mut providers = rule.providers.clone();
        let latency_guard = self.latency.read().await;

        // Sort providers by latency
        providers.sort_by_key(|p| {
            latency_guard
                .get(&(p.identifier.clone(), p.model.clone()))
                .unwrap_or(&u64::MIN)
        });
        console_log!("providers: {:?}; latency: {:?}", providers, latency_guard);

        // Get the fastest provider
        let fastest_provider = providers.first().ok_or_else(|| {
            Error::RuleProviderNotFound("no providers available to pick".to_string())
        })?;

        drop(latency_guard);

        let mut rng = rng();
        // 20% chance to use a random provider for load balancing
        if rng.random_bool(RANDOM_PROVIDER_CHANCE) {
            Ok(providers
                .choose(&mut rng)
                .ok_or_else(|| {
                    Error::RuleProviderNotFound("no providers available to pick".to_string())
                })?
                .clone())
        } else {
            Ok(fastest_provider.clone())
        }
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
        // "X-Title" will be used by service like OpenRouter to identify the request.
        headers.set("X-Title", "one-united")?;

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

    pub fn get_models(&self) -> Vec<String> {
        self.rules.keys().cloned().collect()
    }
}
