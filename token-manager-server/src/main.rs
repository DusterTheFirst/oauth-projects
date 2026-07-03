use std::{env, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Router,
    extract::{FromRef, State},
    http::StatusCode,
    response::Html,
    routing::get,
};
use axum_extra::extract::cookie::Key;
use listenfd::{self, ListenFd};
use oauth2::{ClientId, ClientSecret, reqwest};
use serde_derive::Deserialize;
use tokio::fs;

use crate::{
    activity_tracker::{ActivityTracker, idle_tracking_middleware, watchdog},
    auth::google::{self, GoogleOauthClient, complete_youtube_oauth, start_youtube_oauth},
    state::AppState,
};

mod activity_tracker;
mod auth;
mod state;

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
    let app_state_file =
        PathBuf::from(env::var("APP_STATE_FILE").context("env APP_STATE_FILE should be set")?);
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
    let cookie_key = axum_extra::extract::cookie::Key::from(&master_encryption_key[32..96]);

    let app_state = AppState::load_from_disk(app_state_file, file_key)
        .await
        .context("loading app state")?;

    let oauth_root =
        env::var("OAUTH_REDIRECT_ROOT").context("env OAUTH_REDIRECT_ROOT should be set")?;

    let google_oauth = google::oauth_client(oauth_config.youtube, &oauth_root)
        .context("google oauth client should be configured")?;

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

    let reqwest_client = reqwest::Client::new();

    axum::serve(
        web_listener,
        Router::new()
            .route(
                "/",
                get(|| async { Html("<a href=\"/login/youtube\">Youtube Login</a>") }),
            )
            .route("/login/youtube", get(start_youtube_oauth))
            .route("/oauth/google", get(complete_youtube_oauth))
            .route(
                "/token/youtube",
                get(|State(app_state): State<Arc<AppState>>| async move {
                    match app_state
                        .get_youtube_token(async |token_state| todo!())
                        .await
                    {
                        Ok(token) => Ok(format!("{token:?}")),
                        Err(error) => {
                            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("{error:?}")))
                        }
                    }
                }),
            )
            .route("/login/spotify", get(|| async {}))
            .route("/oauth/spotify", get(|| async {}))
            .route("/token/spotify", get(|| async {}))
            .with_state(RouterState {
                cookie_key,
                google_oauth,
                reqwest_client,
                app_state: Arc::new(app_state),
            })
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

#[derive(Clone)]
struct RouterState {
    cookie_key: Key,
    google_oauth: GoogleOauthClient,
    reqwest_client: reqwest::Client,
    app_state: Arc<AppState>,
}

impl FromRef<RouterState> for Key {
    fn from_ref(state: &RouterState) -> Self {
        state.cookie_key.clone()
    }
}

impl FromRef<RouterState> for Arc<AppState> {
    fn from_ref(state: &RouterState) -> Self {
        state.app_state.clone()
    }
}
