mod config;
mod error;
mod global;
mod kv;
mod router;

use chrono::Utc;
use global::regen_router;
use http::header::AUTHORIZATION;
use humantime::format_duration;
use kv::{get_config_from_kv, save_config_to_kv};
use serde_json::{json, Value};
use worker::{event, Context, Env, Request, Response, RouteContext, Router as WorkerRouter};

use crate::config::Config;
use crate::error::Error;
use crate::global::get_router;

const ONE_API_KEY_SECRET_NAME: &str = "ONE_API_KEY";

#[event(start)]
fn start() {
    console_error_panic_hook::set_once();
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    // Validate the API key from the AUTHORIZATION header.
    let api_key = req
        .headers()
        .get(AUTHORIZATION.as_str())
        .unwrap_or_default()
        .unwrap_or_default();
    // Try to get the API key from the environment secret.
    if let Ok(secret) = env.secret(ONE_API_KEY_SECRET_NAME) {
        // Extract the bearer token from the api key.
        if api_key.trim() != format!("Bearer {}", secret) {
            return Error::Unauthorized.into();
        }
    }

    WorkerRouter::new()
        .get_async("/config", get_config)
        .post_async("/config", save_config)
        .get_async("/stats", get_stats)
        .get_async("/v1/models", get_models)
        .post_async("/v1/chat/completions", route_chat_completions)
        .run(req, env)
        .await
}

async fn get_config(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let config = match get_config_from_kv(&ctx).await {
        Ok(config) => config,
        Err(e) => return e.into(),
    };

    Response::from_json(&config)
}

async fn save_config(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let req_text = match req.text().await {
        Ok(text) => text,
        Err(e) => return Error::from(e).into(),
    };
    let new_config = match Config::build(&req_text) {
        Ok(config) => config,
        Err(e) => return e.into(),
    };
    if let Err(e) = save_config_to_kv(&ctx, new_config.clone()).await {
        return e.into();
    }

    // Regenerate the router with the new config.
    regen_router(new_config).await;

    Response::empty()
}

async fn get_stats(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let router = match get_router(&ctx).await {
        Ok(router) => router,
        Err(e) => return e.into(),
    };
    let stats = router.get_stats().await;

    // Sort by latency.
    let mut sorted_latency = stats.latency.into_iter().collect::<Vec<_>>();
    sorted_latency.sort_by_key(|((_, _), latency)| *latency);
    // Format the latency.
    let formatted_latency: Vec<Value> = sorted_latency
        .into_iter()
        .map(|((identifier, model), latency)| {
            json!({
                "identifier": identifier,
                "model": model,
                "ms": latency
            })
        })
        .collect();

    Response::from_json(&json!({
        "hash": router.hash,
        "created_at": router.created_at,
        "lifetime": format_duration(Utc::now().signed_duration_since(router.created_at).to_std().unwrap_or_default()).to_string(),
        "latency": formatted_latency,
    }))
}

async fn get_models(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let models = match get_router(&ctx).await {
        Ok(router) => router.get_models(),
        Err(e) => return e.into(),
    };

    // Transform into the same format as OpenAI's `/v1/models` API.
    // Ref: https://platform.openai.com/docs/api-reference/models/list
    let formatted_models: Vec<Value> = models
        .into_iter()
        .map(|model| {
            json!({
                "id": model,
                "object": "model",
                "owned_by": "system"
            })
        })
        .collect();

    Response::from_json(&json!({
        "object": "list",
        "data": formatted_models,
    }))
}

async fn route_chat_completions(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let router = match get_router(&ctx).await {
        Ok(router) => router,
        Err(e) => return e.into(),
    };
    match router.route(req).await {
        Ok(resp) => Ok(resp),
        Err(e) => e.into(),
    }
}
