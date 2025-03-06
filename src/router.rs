use std::collections::HashMap;
use std::sync::Arc;

use async_std::sync::RwLock;
use http::header::AUTHORIZATION;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::{rng, seq::IndexedRandom};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use wasm_bindgen::JsValue;
use worker::{console_log, wasm_bindgen, Date, Fetch, Request, RequestInit, Response};

use crate::config::{Config, Identifier, Model, Provider, Rule};
use crate::error::Error;

const STREAM_FIELD: &str = "stream";
const MODEL_FIELD: &str = "model";
const FALLBACK_MODEL: &str = "gpt-4o";
const RANDOM_PROVIDER_CHANCE: f64 = 0.2;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Stats {
    // The latency of each provider in milliseconds.
    pub latency: HashMap<(Identifier, Model), u32>,
}

#[derive(Debug)]
pub struct Router {
    // The hash of the config that is used to generate this router.
    pub hash: String,
    rules: HashMap<Model, Rule>,
    providers: HashMap<Identifier, Provider>,
    // Stats is used to store some stats meta during the router's lifetime.
    stats: RwLock<Stats>,
}

impl Router {
    pub fn new(config: Config, hash: String, stats: Option<Stats>) -> Arc<Self> {
        let mut rules = HashMap::new();
        for rule in config.rules {
            rules.insert(rule.model.clone(), rule.clone());
        }

        let mut providers = HashMap::new();
        for provider in config.providers {
            providers.insert(provider.identifier.clone(), provider.clone());
        }

        Arc::new(Self {
            hash,
            rules,
            providers,
            stats: RwLock::new(stats.unwrap_or_default()),
        })
    }

    async fn update_latency(&self, identifier: &Identifier, model: &Model, latency: u32) {
        let mut stats = self.stats.write().await;
        stats
            .latency
            .insert((identifier.clone(), model.clone()), latency);
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
        let mut model = request_body
            .get(MODEL_FIELD)
            .and_then(|v| v.as_str())
            .unwrap_or(FALLBACK_MODEL)
            .to_string();

        let (provider_identifier, target_model) = match Self::get_raw_model(&model) {
            Some((identifier, target_model)) => {
                model = target_model.clone();
                (identifier, target_model)
            }
            None => {
                // Get the rule for the model.
                let rule = self.get_rule(&model)?;
                // Pick a (provider, model) pair from the rule.
                self.pick_provider_model(rule).await?
            }
        };
        console_log!(
            "picked: {}->{}@@{}",
            model,
            target_model,
            provider_identifier
        );
        // Get the provider.
        let provider = self.get_provider(&provider_identifier)?;
        // Build the request.
        let req = Self::build_request(req, provider, &target_model).await?;
        let (original_url, routed_url) = (original_req.url()?, req.url()?);
        console_log!(
            "routing the {} request: {}@{}--[{}]->{}@{}",
            if is_stream { "stream" } else { "non-stream" },
            original_url,
            model,
            provider_identifier,
            routed_url,
            target_model
        );
        let start = Date::now().as_millis();
        let resp = Fetch::Request(req).send().await?;
        let duration = Date::now().as_millis() - start;
        console_log!(
            "finished routing the {} request: {}@{}--[{}]->{}@{} with status {} in {}ms",
            if is_stream { "stream" } else { "non-stream" },
            original_url,
            model,
            provider_identifier,
            routed_url,
            target_model,
            resp.status_code(),
            duration
        );
        self.update_latency(
            &provider.identifier,
            &target_model,
            if resp.status_code() == 200 {
                duration as u32
            } else {
                u32::MAX
            },
        )
        .await;

        Ok(resp)
    }

    /// Picks a provider from the rule.
    async fn pick_provider_model(&self, rule: &Rule) -> Result<(Identifier, Model), Error> {
        // Flatten the (provider, model) pairs into a single list.
        let mut models: Vec<(Identifier, Model)> =
            Vec::with_capacity(rule.providers.iter().map(|p| p.models.len()).sum());

        for provider in &rule.providers {
            models.extend(
                provider
                    .models
                    .iter()
                    .map(|model| (provider.identifier.clone(), model.clone())),
            );
        }
        // Shuffle the (provider, model) pairs before sorting to avoid always
        // picking the same provider before latency stats are collected.
        let mut rng = rng();
        models.shuffle(&mut rng);
        // Sort the (provider, model) pairs by latency.
        {
            let stats = self.stats.read().await;
            models.sort_by_key(|(identifier, model)| {
                stats
                    .latency
                    .get(&(identifier.clone(), model.clone()))
                    .unwrap_or(&u32::MIN)
            });
            console_log!("{}->{:?}; stats: {:?}", rule.model, models, stats);
        }

        // 20% chance to use a random provider for load balancing.
        Ok(if rng.random_bool(RANDOM_PROVIDER_CHANCE) {
            models
                .choose(&mut rng)
                .ok_or_else(|| {
                    Error::RuleProviderNotFound("no providers available to pick".to_string())
                })?
                .clone()
        } else {
            models
                .first()
                .ok_or_else(|| {
                    Error::RuleProviderNotFound("no providers available to pick".to_string())
                })?
                .clone()
        })
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
        // "HTTP-Referer" and "X-Title" will be used by service like OpenRouter to identify the request.
        headers.set("HTTP-Referer", "https://github.com/JmPotato/one-united")?;
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

    /// If the request model has a pattern like `model@@provider`,
    /// return the raw model name and its provider directly.
    fn get_raw_model(model: &str) -> Option<(Identifier, Model)> {
        if let Some(pos) = model.find("@@") {
            let target_model = model[..pos].to_string();
            let identifier = model[pos + 2..].to_string();
            Some((identifier, target_model))
        } else {
            None
        }
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

    pub async fn get_stats(&self) -> Stats {
        let stats = self.stats.read().await;
        Stats {
            latency: stats.latency.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_raw_model() {
        // Test case 1: Valid format "model@@provider"
        let result = Router::get_raw_model("gpt-4@@openai");
        assert_eq!(result, Some(("openai".to_string(), "gpt-4".to_string())));

        // Test case 2: Another valid format with different values
        let result = Router::get_raw_model("claude-3-opus@@anthropic");
        assert_eq!(
            result,
            Some(("anthropic".to_string(), "claude-3-opus".to_string()))
        );

        // Test case 3: No @@ delimiter
        let result = Router::get_raw_model("gpt-4");
        assert_eq!(result, None);

        // Test case 4: Empty string
        let result = Router::get_raw_model("");
        assert_eq!(result, None);

        // Test case 5: @@ at the beginning
        let result = Router::get_raw_model("@@provider");
        assert_eq!(result, Some(("provider".to_string(), "".to_string())));

        // Test case 6: @@ at the end
        let result = Router::get_raw_model("model@@");
        assert_eq!(result, Some(("".to_string(), "model".to_string())));

        // Test case 7: Multiple @@ delimiters (should only use the first one)
        let result = Router::get_raw_model("model@@provider@@extra");
        assert_eq!(
            result,
            Some(("provider@@extra".to_string(), "model".to_string()))
        );
    }
}
