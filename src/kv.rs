use worker::RouteContext;

use crate::{config::Config, error::Error};

const CONFIG_KV_NAMESPACE: &str = "config";
const CONFIG_KV_KEY: &str = "config";

pub async fn get_config_from_kv(ctx: &RouteContext<()>) -> Result<Config, Error> {
    let kv = ctx.kv(CONFIG_KV_NAMESPACE)?;
    match kv.get(CONFIG_KV_KEY).json::<Config>().await? {
        Some(config) => Ok(config),
        None => Err(Error::NoConfigFoundInKV),
    }
}

pub async fn save_config_to_kv(ctx: &RouteContext<()>, config: Config) -> Result<(), Error> {
    let kv = ctx.kv(CONFIG_KV_NAMESPACE)?;
    kv.put(CONFIG_KV_KEY, config)?.execute().await?;

    Ok(())
}
