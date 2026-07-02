type TokenError = ();

#[tarpc::service]
pub trait TokenManager {
    async fn get_youtube_token() -> Result<String, TokenError>;
    async fn get_spotify_token() -> Result<String, TokenError>;
}
