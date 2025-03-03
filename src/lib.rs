mod config;
mod error;
mod kv;
mod router;

use std::sync::Arc;

use async_std::sync::RwLock;
use http::header::AUTHORIZATION;
use kv::{get_config_from_kv, save_config_to_kv};
use lazy_static::lazy_static;
use serde_json::{json, Value};
use worker::{
    console_log, event, Context, Env, Request, Response, RouteContext, Router as WorkerRouter,
};

use crate::config::Config;
use crate::error::Error;
use crate::router::Router;

const ONE_API_KEY_SECRET_NAME: &str = "ONE_API_KEY";

type GlobalRouter = RwLock<Option<Arc<Router>>>;

lazy_static! {
    pub static ref ROUTER: GlobalRouter = GlobalRouter::new(None);
}

async fn get_router(ctx: RouteContext<()>) -> Result<Arc<Router>, Error> {
    // Prepare the config and hash to validate the consistency later.
    let config = get_config_from_kv(&ctx).await?;
    let hash = config.hash();

    // First try to get existing router.
    if let Some(router) = ROUTER.read().await.as_ref() {
        // Then check if the hash is the same with the config hash in KV.
        if router.hash == hash {
            return Ok(router.clone());
        }
    }

    // Try to generate a new router with the latest config and hash.
    let mut router_write = ROUTER.write().await;
    // Double-check after acquiring write lock.
    if let Some(router) = router_write.as_ref() {
        if router.hash == hash {
            return Ok(router.clone());
        }
    }
    let old_router_hash = match router_write.take() {
        Some(router) => router.hash.clone(),
        None => "".to_string(),
    };
    console_log!(
        "generating a new router with config hash {} -> {}",
        old_router_hash,
        hash
    );
    let new_router = Router::new(config, hash);
    *router_write = Some(new_router.clone());

    Ok(new_router)
}

#[event(start)]
fn start() {
    console_error_panic_hook::set_once();
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    // Validate the API key from the AUTHORIZATION header.
    let api_key = req
        .headers()
        .get(AUTHORIZATION.as_str())?
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
    let new_config = match Config::build(&req.text().await?) {
        Ok(config) => config,
        Err(e) => return e.into(),
    };
    save_config_to_kv(&ctx, new_config.clone()).await?;

    let hash = new_config.hash();
    console_log!("generating a new router with config hash {}", hash);
    let new_router = Router::new(new_config, hash);
    {
        let mut router_guard = ROUTER.write().await;
        drop(router_guard.take());
        *router_guard = Some(new_router);
    }

    Response::empty()
}

async fn get_stats(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let router = match get_router(ctx).await {
        Ok(router) => router,
        Err(e) => return e.into(),
    };
    let latency_stats = router.get_latency_stats().await;

    // Sort by latency.
    let mut sorted_stats = latency_stats.into_iter().collect::<Vec<_>>();
    sorted_stats.sort_by_key(|((_, _), latency)| *latency);
    // Format the stats.
    let formatted_latency_stats: Vec<Value> = sorted_stats
        .into_iter()
        .map(|((identifier, model), latency)| {
            json!({
                "identifier": identifier,
                "model": model,
                "latency_ms": latency
            })
        })
        .collect();

    Response::from_json(&json!({
        "hash": router.hash,
        "latency_stats": formatted_latency_stats,
    }))
}

async fn get_models(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let models = match get_router(ctx).await {
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
    match get_router(ctx).await {
        Ok(router) => router.route(req).await.map_err(|e| e.into()),
        Err(e) => e.into(),
    }
}
