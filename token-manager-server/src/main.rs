use std::{env, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use axum::Router;
use listenfd::{self, ListenFd};
use oauth2::{
    AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl, basic::BasicClient, reqwest::get,
};
use serde_derive::Deserialize;
use tokio::fs;

use crate::activity_tracker::{ActivityTracker, idle_tracking_middleware, watchdog};

mod activity_tracker;
mod auth;

struct AppState {
    youtube: TokenState,
    spotify: TokenState,
}

struct TokenState {
    refresh_token: Option<String>,
    access_token: String,
}

#[derive(Deserialize)]
struct OauthConfig {
    youtube: ClientIdSecret,
    spotify: ClientIdSecret,
}

#[derive(Deserialize)]
struct ClientIdSecret {
    client_id: ClientId,
    client_secret: ClientSecret,
}

#[tokio_macros::main]
async fn main() -> anyhow::Result<()> {
    let credentials = PathBuf::from(
        env::var("CREDENTIALS_DIRECTORY").context("env CREDENTIALS_DIRECTORY should be set")?,
    );
    let oauth_config = toml::from_str::<OauthConfig>(
        &fs::read_to_string(credentials.join("oauth-config.toml"))
            .await
            .context("oauth-config.toml should be read")?,
    )
    .context("oauth-config.toml should follow the expected schema")?;
    let master_encryption_key = fs::read_to_string(credentials.join("encryption.key"))
        .await
        .context("encryption.key should be read")?;

    let master_encryption_key =
        hex::decode(master_encryption_key.trim()).context("encryption.key should be hex digits")?;
    anyhow::ensure!(
        master_encryption_key.len() == 96,
        "encryption.key should be exactly 96 bytes (192 hex chars)"
    );

    let file_key = chacha20poly1305::Key::try_from(&master_encryption_key[..32])
        .expect("32 bits should be the length for chacha20poly1305");
    let axum_key = axum_extra::extract::cookie::Key::from(&master_encryption_key[32..96]);

    let hostname =
        env::var("OAUTH_REDIRECT_ROOT").context("env OAUTH_REDIRECT_ROOT should be set")?;

    let youtube_client = BasicClient::new(oauth_config.youtube.client_id)
        .set_client_secret(oauth_config.youtube.client_secret)
        .set_auth_uri(
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                .expect("auth url should be a valid url"),
        )
        .set_token_uri(
            TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
                .expect("token url should be a valid url"),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(
            RedirectUrl::new(format!("{hostname}/oauth/youtube"))
                .context("redirect url should be a valid url")?,
        );

    let mut listenfd = ListenFd::from_env();
    let web_listener = listenfd
        .take_tcp_listener(0)
        .context("tcp listener should be taken")?
        .context("socket activation file descriptor should exist for web server")?;

    web_listener
        .set_nonblocking(true)
        .expect("socket should become non-blocking");

    let web_listener = tokio::net::TcpListener::from_std(web_listener)
        .expect("std socket should be valid tokio tcp listener");

    let tracker = Arc::new(ActivityTracker::new(Duration::from_secs(3)));

    tokio::spawn(watchdog(tracker.clone()));

    axum::serve(
        web_listener,
        Router::new()
            .route("/login/youtube", get())
            .layer(axum::middleware::from_fn_with_state(
                tracker.clone(),
                idle_tracking_middleware,
            )),
    )
    .with_graceful_shutdown(async move {
        tracker.cancellation_token().cancelled().await;
        println!("idle timeout reached. shutting down gracefully...");
    })
    .await
    .unwrap();

    Ok(())
}
