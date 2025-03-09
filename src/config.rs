use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use worker_kv::ToRawKvValue;

use crate::error::Error;

pub type Model = String;
pub type Identifier = String;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    pub model: Model,
    pub providers: Vec<RuleProvider>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RuleProvider {
    pub identifier: Identifier,
    pub models: Vec<Model>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Provider {
    name: String,
    pub identifier: Identifier,
    pub endpoint: String,
    #[serde(default = "default_path")]
    pub path: String,
    pub api_key: String,
    models: Vec<Model>,
}

fn default_path() -> String {
    "/v1/chat/completions".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub providers: Vec<Provider>,
}

impl Config {
    pub fn build_from_json(data: &str) -> Result<Self, Error> {
        let config: Config = serde_json::from_str(data)?;
        config.validate()?;
        Ok(config)
    }

    pub fn build_from_yaml(data: &str) -> Result<Self, Error> {
        let config: Config = serde_yaml::from_str(data)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Error> {
        // Check if the providers are unique.
        let mut providers: HashMap<Identifier, Vec<Model>> = HashMap::new();
        for provider in &self.providers {
            // Check if the provider configuration is valid.
            if provider.identifier.is_empty() {
                return Err(Error::ProviderInvalidIdentifier(
                    provider.identifier.clone(),
                ));
            }
            if provider.endpoint.is_empty() {
                return Err(Error::ProviderInvalidEndpoint(provider.endpoint.clone()));
            }
            if provider.models.is_empty() {
                return Err(Error::ProviderInvalidModels(provider.identifier.clone()));
            }
            // Check if the provider identifier is unique.
            if providers.contains_key(&provider.identifier) {
                return Err(Error::ProviderIdentifierNotUnique(
                    provider.identifier.clone(),
                ));
            }
            providers.insert(provider.identifier.clone(), provider.models.clone());
        }
        // Check if the rules are unique.
        let mut rule_models = std::collections::HashSet::new();
        for rule in &self.rules {
            if !rule_models.insert(rule.model.clone()) {
                return Err(Error::RuleModelNotUnique(rule.model.clone()));
            }
        }
        // Check if the rules are valid.
        for rule in &self.rules {
            // Check if the providers are valid.
            for rule_provider in &rule.providers {
                if !providers.contains_key(&rule_provider.identifier) {
                    return Err(Error::RuleProviderNotFound(
                        rule_provider.identifier.clone(),
                    ));
                }
            }
            // Check each provider in the rule to see if the model mapping is valid.
            for rule_provider in &rule.providers {
                let provider_models = providers.get(&rule_provider.identifier);
                if provider_models.is_none() {
                    return Err(Error::RuleProviderNotFound(
                        rule_provider.identifier.clone(),
                    ));
                }

                let provider_models = provider_models.unwrap();
                // Check if the rule provider has at least one model
                if rule_provider.models.is_empty() {
                    return Err(Error::ProviderInvalidModels(
                        rule_provider.identifier.clone(),
                    ));
                }
                // Check if all models in the rule provider are available in the provider
                for model in &rule_provider.models {
                    if !provider_models.contains(model) {
                        return Err(Error::RuleModelNotFound(
                            model.clone(),
                            rule_provider.identifier.clone(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn hash(&self) -> String {
        blake3::hash(
            self.raw_kv_value()
                .unwrap_or_default()
                .as_string()
                .unwrap_or_default()
                .as_bytes(),
        )
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config_valid() {
        let data = r#"
{
  "rules": [
    {
      "model": "model0",
      "providers": [
        {
          "identifier": "provider0",
          "models": ["model0-1"]
        },
        {
          "identifier": "provider1",
          "models": ["model0-2"]
        },
        {
          "identifier": "provider2",
          "models": ["model0-3"]
        }
      ]
    }
  ],
  "providers": [
    {
      "name": "Provider 0",
      "identifier": "provider0",
      "endpoint": "https://ark.cn-beijing.volces.com/api",
      "path": "/v3/chat/completions",
      "api_key": "sk-provider0",
      "models": [
        "model0-1"
      ]
    },
    {
      "name": "Provider 1",
      "identifier": "provider1",
      "endpoint": "https://api.lkeap.cloud.tencent.com",
      "api_key": "sk-provider1",
      "models": [
        "model0-2"
      ]
    },
    {
      "name": "Provider 2",
      "identifier": "provider2",
      "endpoint": "https://api.deepseek.com",
      "api_key": "sk-provider2",
      "models": [
        "model0-3"
      ]
    }
  ]
}
"#;
        let config = Config::build_from_json(data).expect("Failed to build valid config");

        // Validate the number of rules and providers.
        assert_eq!(config.rules.len(), 1, "Expected exactly one rule");
        assert_eq!(config.providers.len(), 3, "Expected three providers");

        // Validate rule fields.
        let rule = &config.rules[0];
        assert_eq!(rule.model, "model0", "Unexpected rule model");
        assert_eq!(rule.providers.len(), 3, "Expected three providers in rule");

        // Validate each rule provider.
        let expected_rule_providers = vec![
            ("provider0", vec!["model0-1"]),
            ("provider1", vec!["model0-2"]),
            ("provider2", vec!["model0-3"]),
        ];
        for (i, (expected_identifier, expected_models)) in
            expected_rule_providers.iter().enumerate()
        {
            let rule_provider = &rule.providers[i];
            assert_eq!(
                rule_provider.identifier, *expected_identifier,
                "Unexpected identifier for rule provider at index {}",
                i
            );
            assert_eq!(
                rule_provider.models, *expected_models,
                "Unexpected models for rule provider at index {}",
                i
            );
        }

        // Validate provider fields.
        // Provider 0: has an overridden "path"
        let provider0 = config
            .providers
            .iter()
            .find(|p| p.identifier == "provider0")
            .expect("Provider0 not found");
        assert_eq!(
            provider0.name, "Provider 0",
            "Unexpected name for provider0"
        );
        assert_eq!(
            provider0.endpoint, "https://ark.cn-beijing.volces.com/api",
            "Unexpected endpoint for provider0"
        );
        assert_eq!(
            provider0.path, "/v3/chat/completions",
            "Unexpected path for provider0"
        );
        assert_eq!(
            provider0.api_key, "sk-provider0",
            "Unexpected api_key for provider0"
        );
        assert_eq!(
            provider0.models,
            vec!["model0-1"],
            "Unexpected models for provider0"
        );

        // Provider 1 and Provider 2: should use the default "/v1/chat/completions" path.
        let provider1 = config
            .providers
            .iter()
            .find(|p| p.identifier == "provider1")
            .expect("Provider1 not found");
        assert_eq!(
            provider1.name, "Provider 1",
            "Unexpected name for provider1"
        );
        assert_eq!(
            provider1.endpoint, "https://api.lkeap.cloud.tencent.com",
            "Unexpected endpoint for provider1"
        );
        assert_eq!(
            provider1.path, "/v1/chat/completions",
            "Unexpected default path for provider1"
        );
        assert_eq!(
            provider1.api_key, "sk-provider1",
            "Unexpected api_key for provider1"
        );
        assert_eq!(
            provider1.models,
            vec!["model0-2"],
            "Unexpected models for provider1"
        );

        let provider2 = config
            .providers
            .iter()
            .find(|p| p.identifier == "provider2")
            .expect("Provider2 not found");
        assert_eq!(
            provider2.name, "Provider 2",
            "Unexpected name for provider2"
        );
        assert_eq!(
            provider2.endpoint, "https://api.deepseek.com",
            "Unexpected endpoint for provider2"
        );
        assert_eq!(
            provider2.path, "/v1/chat/completions",
            "Unexpected default path for provider2"
        );
        assert_eq!(
            provider2.api_key, "sk-provider2",
            "Unexpected api_key for provider2"
        );
        assert_eq!(
            provider2.models,
            vec!["model0-3"],
            "Unexpected models for provider2"
        );
    }

    #[test]
    fn test_empty_provider_identifier() {
        let config = Config {
            providers: vec![Provider {
                name: "Test Provider".to_string(),
                identifier: "".to_string(),
                endpoint: "https://example.com/api".to_string(),
                path: "/v1/chat/completions".to_string(),
                api_key: "some_key".to_string(),
                models: vec!["model1".to_string()],
            }],
            rules: vec![],
        };

        let err = config.validate().unwrap_err();
        match err {
            Error::ProviderInvalidIdentifier(id) => assert_eq!(id, ""),
            _ => panic!("Expected ProviderInvalidIdentifier error"),
        }
    }

    #[test]
    fn test_empty_provider_endpoint() {
        let config = Config {
            providers: vec![Provider {
                name: "Test Provider".to_string(),
                identifier: "provider1".to_string(),
                endpoint: "".to_string(),
                path: "/v1/chat/completions".to_string(),
                api_key: "some_key".to_string(),
                models: vec!["model1".to_string()],
            }],
            rules: vec![],
        };

        let err = config.validate().unwrap_err();
        match err {
            Error::ProviderInvalidEndpoint(ep) => assert_eq!(ep, ""),
            _ => panic!("Expected ProviderInvalidEndpoint error"),
        }
    }

    #[test]
    fn test_empty_provider_models() {
        let config = Config {
            providers: vec![Provider {
                name: "Test Provider".to_string(),
                identifier: "provider1".to_string(),
                endpoint: "https://example.com/api".to_string(),
                path: "/v1/chat/completions".to_string(),
                api_key: "some_key".to_string(),
                models: vec![],
            }],
            rules: vec![],
        };

        let err = config.validate().unwrap_err();
        match err {
            Error::ProviderInvalidModels(id) => assert_eq!(id, "provider1"),
            _ => panic!("Expected ProviderInvalidModels error"),
        }
    }

    #[test]
    fn test_duplicate_provider_identifier() {
        let config = Config {
            providers: vec![
                Provider {
                    name: "Test Provider 1".to_string(),
                    identifier: "provider1".to_string(),
                    endpoint: "https://example.com/api1".to_string(),
                    path: "/v1/chat/completions".to_string(),
                    api_key: "some_key1".to_string(),
                    models: vec!["model1".to_string()],
                },
                Provider {
                    name: "Test Provider 2".to_string(),
                    identifier: "provider1".to_string(),
                    endpoint: "https://example.com/api2".to_string(),
                    path: "/v1/chat/completions".to_string(),
                    api_key: "some_key2".to_string(),
                    models: vec!["model2".to_string()],
                },
            ],
            rules: vec![],
        };

        let err = config.validate().unwrap_err();
        match err {
            Error::ProviderIdentifierNotUnique(id) => assert_eq!(id, "provider1"),
            _ => panic!("Expected ProviderIdentifierNotUnique error"),
        }
    }

    #[test]
    fn test_duplicate_rule_model() {
        let config = Config {
            providers: vec![Provider {
                name: "Test Provider".to_string(),
                identifier: "provider1".to_string(),
                endpoint: "https://example.com/api".to_string(),
                path: "/v1/chat/completions".to_string(),
                api_key: "some_key".to_string(),
                models: vec!["model1".to_string()],
            }],
            rules: vec![
                Rule {
                    model: "ruleModel".to_string(),
                    providers: vec![RuleProvider {
                        identifier: "provider1".to_string(),
                        models: vec!["model1".to_string()],
                    }],
                },
                Rule {
                    model: "ruleModel".to_string(),
                    providers: vec![RuleProvider {
                        identifier: "provider1".to_string(),
                        models: vec!["model1".to_string()],
                    }],
                },
            ],
        };

        let err = config.validate().unwrap_err();
        match err {
            Error::RuleModelNotUnique(model) => assert_eq!(model, "ruleModel"),
            _ => panic!("Expected RuleModelNotUnique error"),
        }
    }

    #[test]
    fn test_rule_provider_not_found() {
        let config = Config {
            providers: vec![Provider {
                name: "Test Provider".to_string(),
                identifier: "provider1".to_string(),
                endpoint: "https://example.com/api".to_string(),
                path: "/v1/chat/completions".to_string(),
                api_key: "some_key".to_string(),
                models: vec!["model1".to_string()],
            }],
            rules: vec![Rule {
                model: "ruleModel".to_string(),
                providers: vec![RuleProvider {
                    identifier: "nonexistent_provider".to_string(),
                    models: vec!["model1".to_string()],
                }],
            }],
        };

        let err = config.validate().unwrap_err();
        match err {
            Error::RuleProviderNotFound(id) => assert_eq!(id, "nonexistent_provider"),
            _ => panic!("Expected RuleProviderNotFound error"),
        }
    }

    #[test]
    fn test_rule_model_not_found() {
        let config = Config {
            providers: vec![Provider {
                name: "Test Provider".to_string(),
                identifier: "provider1".to_string(),
                endpoint: "https://example.com/api".to_string(),
                path: "/v1/chat/completions".to_string(),
                api_key: "some_key".to_string(),
                models: vec!["model1".to_string()],
            }],
            rules: vec![Rule {
                model: "ruleModel".to_string(),
                providers: vec![RuleProvider {
                    identifier: "provider1".to_string(),
                    models: vec!["nonexistent_model".to_string()],
                }],
            }],
        };

        let err = config.validate().unwrap_err();
        match err {
            Error::RuleModelNotFound(model, provider_id) => {
                assert_eq!(model, "nonexistent_model");
                assert_eq!(provider_id, "provider1");
            }
            _ => panic!("Expected RuleModelNotFound error"),
        }
    }
}
