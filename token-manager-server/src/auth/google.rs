use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use oauth2::{
    AuthUrl, AuthorizationCode, CsrfToken, EndpointNotSet, EndpointSet, RedirectUrl, RevocationUrl,
    TokenResponse as _, TokenUrl, basic::BasicClient,
};
use serde_derive::{Deserialize, Serialize};
use time::Timestamp;

use crate::{ClientIdSecret, RouterState, TokenState};

#[derive(Clone, Debug)]
pub struct GoogleOauthClient(
    Arc<BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointSet, EndpointSet>>,
);

pub fn oauth_client(
    client_info: ClientIdSecret,
    oauth_root: &str,
) -> anyhow::Result<GoogleOauthClient> {
    Ok(GoogleOauthClient(Arc::new(
        BasicClient::new(client_info.client_id)
            .set_client_secret(client_info.client_secret)
            .set_auth_uri(
                AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string())
                    .expect("auth url should be a valid url"),
            )
            .set_token_uri(
                TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                    .expect("token url should be a valid url"),
            )
            .set_revocation_url(
                RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())
                    .expect("revocation url should be a valid url"),
            )
            .set_redirect_uri(
                RedirectUrl::new(format!("{oauth_root}/oauth/google"))
                    .context("redirect url should be a valid url")?,
            ),
    )))
}

const COOKIE_NAME: &str = "oauth_state";

pub async fn start_youtube_oauth(
    State(RouterState { google_oauth, .. }): State<RouterState>,
    jar: PrivateCookieJar,
) -> impl IntoResponse {
    let (google_url, csrf_token) = google_oauth
        .0
        .authorize_url(CsrfToken::new_random)
        .add_scope(oauth2::Scope::new(
            "https://www.googleapis.com/auth/youtube.readonly".to_string(),
        ))
        .add_scope(oauth2::Scope::new(
            "https://www.googleapis.com/auth/youtube".to_string(),
        ))
        // The following 2 parameters ask for a refresh token
        .add_extra_param("access_type", "offline")
        .add_extra_param("prompt", "consent")
        .url();

    let state_cookie = Cookie::build((COOKIE_NAME, csrf_token.into_secret()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::minutes(5))
        .build();

    (jar.add(state_cookie), Redirect::to(google_url.as_str()))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OAuthRedirectQueryParams {
    Success {
        code: AuthorizationCode,
        state: CsrfToken,
    },
    Failure {
        error: String,
    },
}

pub async fn complete_youtube_oauth(
    State(RouterState {
        google_oauth,
        reqwest_client,
        ..
    }): State<RouterState>,
    jar: PrivateCookieJar,
    Query(query): Query<OAuthRedirectQueryParams>,
) -> impl IntoResponse {
    let code = match query {
        OAuthRedirectQueryParams::Failure { error } => {
            return Err((
                StatusCode::FAILED_DEPENDENCY,
                format!("error from google: {error}"),
            ));
        }
        OAuthRedirectQueryParams::Success { code, state } => {
            if let Some(cookie) = jar.get(COOKIE_NAME)
                && cookie.value() == state.secret()
            {
                code
            } else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "CSRF token does not match oauth state".to_string(),
                ));
            }
        }
    };

    let token_response = google_oauth
        .0
        .exchange_code(code)
        .request_async(&reqwest_client)
        .await
        .unwrap();

    let acquired_at = Timestamp::now();
    let Some(expires_at) = token_response
        .expires_in()
        .map(|expires_in| acquired_at + expires_in)
    else {
        return Err((
            StatusCode::FAILED_DEPENDENCY,
            "offline authorization missing expires_in".to_string(),
        ));
    };

    let access_token = token_response.access_token().clone();
    let Some(refresh_token) = token_response.refresh_token().cloned() else {
        return Err((
            StatusCode::FAILED_DEPENDENCY,
            "offline authorization should always provide a refresh token".to_string(),
        ));
    };

    let token_state = TokenState {
        acquired_at,
        expires_at,
        access_token,
        refresh_token,
    };

    Ok((jar.remove(COOKIE_NAME), Redirect::to("/")))
}
