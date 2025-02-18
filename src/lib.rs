mod config;
mod error;
mod router;

use async_std::sync::RwLock;
use http::header::AUTHORIZATION;
use lazy_static::lazy_static;
use serde_json::json;
use worker::{
    console_log, event, Context, Env, Fetch, Headers, Request, Response, RouteContext,
    Router as WorkerRouter,
};

use crate::config::Config;
use crate::error::Error;
use crate::router::Router;

const ONE_API_KEY_SECRET_NAME: &str = "ONE_API_KEY";
const CONFIG_KV_NAMESPACE: &str = "config";
const CONFIG_KV_KEY: &str = "config";

type GlobalRouter = RwLock<Option<Router>>;

lazy_static! {
    pub static ref ROUTER: GlobalRouter = GlobalRouter::new(None);
}

async fn get_router(ctx: RouteContext<()>) -> Result<Router, Error> {
    {
        let router_guard = ROUTER.read().await;
        if router_guard.is_some() {
            return Ok(router_guard.clone().unwrap());
        }
    }

    {
        let config = ctx
            .kv(CONFIG_KV_NAMESPACE)?
            .get(CONFIG_KV_KEY)
            .json::<Config>()
            .await?;
        if config.is_none() {
            return Err(Error::NoConfigFoundInKV);
        }
        let mut router_write = ROUTER.write().await;
        // Double-check in case the router was initialized in the meantime.
        if router_write.is_some() {
            return Ok(router_write.clone().unwrap());
        }

        let new_router = Router::new(config.unwrap());
        *router_write = Some(new_router);
    }

    Ok(ROUTER.read().await.clone().unwrap())
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
    match env.secret(ONE_API_KEY_SECRET_NAME) {
        Ok(secret) => {
            // Extract the bearer token from the api key.
            if api_key.trim() != format!("Bearer {}", secret.to_string()) {
                return Ok(Response::error(
                    json!({
                      "error": {
                        "code": "AuthenticationError",
                        "message": "The API key in the request is missing or invalid.",
                        "type": "Unauthorized"
                      }
                    })
                    .to_string(),
                    401,
                )?);
            }
        }
        Err(_) => {}
    }

    WorkerRouter::new()
        .get_async("/config", get_config)
        .post_async("/config", save_config)
        .post_async("/v1/chat/completions", proxy_chat_completions)
        .run(req, env)
        .await
}

async fn get_config(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let config = ctx
        .kv(CONFIG_KV_NAMESPACE)?
        .get(CONFIG_KV_KEY)
        .json::<Config>()
        .await?;

    Ok(Response::from_json(&config)?)
}

async fn save_config(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let new_config = req.json::<Config>().await?;
    ctx.kv(CONFIG_KV_NAMESPACE)?
        .put(CONFIG_KV_KEY, new_config.clone())?
        .execute()
        .await?;

    let new_router = Router::new(new_config);
    {
        let mut router_guard = ROUTER.write().await;
        *router_guard = Some(new_router);
    }

    Response::empty()
}

async fn proxy_chat_completions(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let original_url = req.url()?;
    let (new_req, is_stream) = get_router(ctx).await?.route(req).await?;
    let new_url = new_req.url()?;
    let resp = Fetch::Request(new_req).send().await?;
    console_log!(
        "finished routing from {} to {} with status {}",
        original_url,
        new_url,
        resp.status_code()
    );

    if is_stream {
        process_stream_response(resp).await
    } else {
        process_non_stream_response(resp).await
    }
}

async fn process_stream_response(mut resp: Response) -> worker::Result<Response> {
    let headers = build_response_headers(&resp, true);
    Ok(Response::from_stream(resp.stream()?)?.with_headers(headers))
}

fn build_response_headers(resp: &Response, is_stream: bool) -> Headers {
    let mut headers = resp.headers().clone();
    headers.set("Access-Control-Allow-Origin", "*").unwrap();
    headers.set("X-Proxy-Engine", "worker-rs").unwrap();

    if is_stream {
        headers.set("Content-Type", "text/event-stream").unwrap();
        headers.delete("Content-Length").unwrap();
    }

    headers
}

async fn process_non_stream_response(mut resp: Response) -> worker::Result<Response> {
    let headers = build_response_headers(&resp, false);
    Ok(Response::from_bytes(resp.bytes().await?)?.with_headers(headers))
}
