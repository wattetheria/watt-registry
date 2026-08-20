use anyhow::Result;
use registry_server::{RegistryConfig, RegistryState, serve};

#[tokio::main]
async fn main() -> Result<()> {
    let config = RegistryConfig::from_env()?;
    let state_config = config.clone();
    let state =
        tokio::task::spawn_blocking(move || RegistryState::from_config(&state_config)).await??;
    serve(config, state).await
}
