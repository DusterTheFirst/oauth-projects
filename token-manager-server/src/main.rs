use std::{
    env,
    io::{ErrorKind, Read, Write},
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use atomic_write_file::AtomicWriteFile;
use axum::{Router, extract::FromRef, routing::get};
use axum_extra::extract::cookie::Key;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit as _, Nonce,
    aead::{Aead as _, Generate as _},
};
use listenfd::{self, ListenFd};
use oauth2::{AccessToken, ClientId, ClientSecret, RefreshToken, reqwest};
use serde_derive::{Deserialize, Serialize};
use time::Timestamp;
use tokio::{
    fs::{self, File},
    io::AsyncReadExt as _,
    sync::{Mutex, MutexGuard},
};

use crate::{
    activity_tracker::{ActivityTracker, idle_tracking_middleware, watchdog},
    auth::google::{self, GoogleOauthClient, complete_youtube_oauth, start_youtube_oauth},
};

mod activity_tracker;
mod auth;

struct AppState {
    path: PathBuf,
    key: chacha20poly1305::Key,
    data: Mutex<AppStateOnDisk>,
}

#[derive(Deserialize, Serialize)]
struct AppStateOnDisk {
    youtube: Option<TokenState>,
    spotify: Option<TokenState>,
}

#[derive(Deserialize, Serialize)]
struct TokenState {
    /// The initial acquisition timestamp
    acquired_at: Timestamp,

    /// The current expiration of the access token
    expires_at: Timestamp,

    access_token: AccessToken,
    refresh_token: RefreshToken,
}

impl AppState {
    pub async fn insert_youtube_token(&self, token_state: TokenState) {
        let mut data = self.data.lock().await;
        data.youtube = Some(token_state);
    }

    pub async fn get_youtube_token(
        &self,
        refresh: impl AsyncFn(&TokenState) -> anyhow::Result<Option<TokenState>>,
    ) -> anyhow::Result<Option<AccessToken>> {
        let mut data = self.data.lock().await;

        let Some(youtube) = &mut data.youtube else {
            return Ok(None);
        };

        if youtube.expires_at > (Timestamp::now() + Duration::from_mins(1)) {
            return Ok(Some(youtube.access_token.clone()));
        }

        data.youtube = refresh(youtube)
            .await
            .context("should refresh youtube token")?;

        Self::save_to_disk(&self.key, &self.path, &data).context("saving new state to file")?;

        Ok(data.youtube.as_ref().map(|yt| yt.access_token.clone()))
    }

    fn save_to_disk(
        key: &chacha20poly1305::Key,
        path: &Path,
        data: &MutexGuard<'_, AppStateOnDisk>,
    ) -> anyhow::Result<()> {
        tokio::task::block_in_place(|| {
            let app_state =
                toml::to_string(data.deref()).expect("app state should be serializable to toml");

            let cipher = ChaCha20Poly1305::new(key);
            let nonce = Nonce::generate(); // MUST be unique per message
            let ciphertext = cipher
                .encrypt(&nonce, app_state.as_bytes())
                .expect("plaintext should not be too long");

            let mut file =
                AtomicWriteFile::open(path).context("app state file should be opened")?;

            file.write_all(nonce.as_slice())
                .context("writing app state nonce")?;
            file.write_all(&ciphertext)
                .context("writing app state cyphertext")?;

            file.commit().context("file should be comitted")?;

            Ok(())
        })
    }

    pub async fn load_from_disk(path: PathBuf, key: chacha20poly1305::Key) -> anyhow::Result<Self> {
        let mut file = match File::open(&path).await {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    key,
                    data: Mutex::new(AppStateOnDisk {
                        spotify: None,
                        youtube: None,
                    }),
                });
            }
            Err(error) => {
                return Err(error).context("app state file should be opened");
            }
        };

        let mut nonce = [0; size_of::<Nonce>()];
        file.read_exact(&mut nonce)
            .await
            .context("reading app state nonce");
        let nonce = Nonce::from(nonce);

        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)
            .await
            .context("reading app state cyphertext")?;

        let cipher = ChaCha20Poly1305::new(&key);
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_slice())?;

        Ok(Self {
            path,
            key,
            data: Mutex::new(toml::from_slice(&plaintext).context("app state should be valid")?),
        })
    }
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
            .route("/login/youtube", get(start_youtube_oauth))
            .route("/oauth/google", get(complete_youtube_oauth))
            .route("/token/youtube", get(|| async {}))
            .route("/login/spotify", get(|| async {}))
            .route("/oauth/spotify", get(|| async {}))
            .route("/token/spotify", get(|| async {}))
            .with_state(RouterState {
                cookie_key,
                google_oauth,
                reqwest_client,
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
}

impl FromRef<RouterState> for Key {
    fn from_ref(state: &RouterState) -> Self {
        state.cookie_key.clone()
    }
}
