use std::sync::Arc;

use async_std::sync::RwLock;
use lazy_static::lazy_static;
use worker::{console_log, RouteContext};

use crate::{config::Config, error::Error, kv::get_config_from_kv, router::Router};

type GlobalRouter = RwLock<Option<Arc<Router>>>;

lazy_static! {
    pub static ref ROUTER: GlobalRouter = GlobalRouter::new(None);
}

pub async fn get_router(ctx: &RouteContext<()>) -> Result<Arc<Router>, Error> {
    // Prepare the config and hash to validate the consistency later.
    let config = get_config_from_kv(ctx).await?;
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
    let old_router = router_write.take();
    let old_router_hash = old_router.as_ref().map(|router| router.hash.clone());
    console_log!(
        "generating a new router with config hash {:?} -> {}",
        old_router_hash,
        hash
    );
    let new_router = Router::new(
        config,
        hash,
        match old_router {
            Some(router) => Some(router.get_stats().await),
            None => None,
        },
    );
    *router_write = Some(new_router.clone());

    Ok(new_router)
}

pub async fn regen_router(config: Config) {
    let hash = config.hash();
    console_log!("generating a new router with config hash {}", hash);
    let mut router_write = ROUTER.write().await;
    *router_write = Some(Router::new(
        config,
        hash,
        match router_write.take() {
            Some(router) => Some(router.get_stats().await),
            None => None,
        },
    ));
}
