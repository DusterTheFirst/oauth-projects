use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use oauth2::{
    AuthorizationCode, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, RedirectUrl,
    TokenResponse as _, basic::BasicClient,
};
use serde_derive::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{OauthStaticConfig, RouterState, state::TokenState};

#[derive(Clone, Debug)]
pub struct OauthClient(
    Arc<BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointSet>>,
);

pub fn oauth_client(
    provider_name: &str,
    provider_config: OauthStaticConfig,
    oauth_root: &str,
) -> anyhow::Result<OauthClient> {
    Ok(OauthClient(Arc::new(
        BasicClient::new(provider_config.client_id)
            .set_client_secret(provider_config.client_secret)
            .set_auth_uri(provider_config.auth_url)
            .set_token_uri(provider_config.token_url)
            .set_revocation_url_option(provider_config.revocation_url)
            .set_redirect_uri(
                RedirectUrl::new(format!("{oauth_root}/oauth/{provider_name}"))
                    .context("redirect url should be a valid url")?,
            ),
    )))
}

fn cookie_name(provider_name: &str) -> String {
    format!("oauth_state__{provider_name}")
}

pub async fn start_auth(
    Path(provider): Path<String>,
    State(RouterState { oauth, .. }): State<RouterState>,
    jar: PrivateCookieJar,
) -> impl IntoResponse {
    let Some((OauthClient(oauth), config)) = oauth.get(&provider) else {
        return Err(StatusCode::NOT_FOUND);
    };

    let mut auth = oauth
        .authorize_url(CsrfToken::new_random)
        .add_scopes(config.scope.iter().cloned());

    for (name, value) in &config.extra {
        auth = auth.add_extra_param(name, value)
    }

    let (google_url, csrf_token) = auth.url();

    let state_cookie = Cookie::build((cookie_name(&provider), csrf_token.into_secret()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::minutes(5))
        .build();

    Ok((jar.add(state_cookie), Redirect::to(google_url.as_str())))
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

pub async fn complete_auth(
    Path(provider): Path<String>,
    Query(query): Query<OAuthRedirectQueryParams>,
    State(RouterState {
        oauth,
        reqwest_client,
        app_state,
        ..
    }): State<RouterState>,
    jar: PrivateCookieJar,
) -> impl IntoResponse {
    let cookie_name = cookie_name(&provider);

    let code = match query {
        OAuthRedirectQueryParams::Failure { error } => {
            return Err((
                StatusCode::FAILED_DEPENDENCY,
                format!("error from provider: {error}"),
            ));
        }
        OAuthRedirectQueryParams::Success { code, state } => {
            if let Some(cookie) = jar.get(&cookie_name)
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

    let Some((OauthClient(oauth), _)) = oauth.get(&provider) else {
        return Err((StatusCode::NOT_FOUND, String::new()));
    };

    let token_response = oauth
        .exchange_code(code)
        .request_async(&reqwest_client)
        .await
        .unwrap();

    let acquired_at = OffsetDateTime::now_utc();
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

    if let Err(error) = app_state.insert_token(provider, token_state).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to save youtube token: {error:?}"),
        ));
    };

    Ok((jar.remove(cookie_name), Redirect::to("/")))
}
