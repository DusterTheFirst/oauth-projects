use std::{
    io::{ErrorKind, Write},
    ops::Deref,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;
use atomic_write_file::AtomicWriteFile;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit as _, Nonce,
    aead::{Aead as _, Generate as _},
};
use oauth2::{AccessToken, RefreshToken};
use serde_derive::{Deserialize, Serialize};
use time::{OffsetDateTime, Timestamp};
use tokio::{
    fs::File,
    io::AsyncReadExt as _,
    sync::{Mutex, MutexGuard},
};

pub struct AppState {
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
pub struct TokenState {
    /// The initial acquisition timestamp
    #[serde(with = "time::serde::rfc3339")]
    pub acquired_at: OffsetDateTime,

    /// The current expiration of the access token
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,

    pub access_token: AccessToken,
    pub refresh_token: RefreshToken,
}

impl AppState {
    pub async fn insert_youtube_token(&self, token_state: TokenState) -> anyhow::Result<()> {
        let mut data = self.data.lock().await;
        data.youtube = Some(token_state);

        Self::save_to_disk(&self.key, &self.path, &data).context("saving new state to file")
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
