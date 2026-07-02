use axum::{
    extract::State,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use oauth2::{
    Client, EmptyExtraTokenFields, EndpointNotSet, EndpointSet, RevocationErrorResponseType,
    StandardErrorResponse, StandardRevocableToken, StandardTokenIntrospectionResponse,
    StandardTokenResponse,
    basic::{BasicErrorResponseType, BasicTokenType},
};

pub async fn start_google_oauth(
    jar: PrivateCookieJar,
    State(oauth_client): State<
        Client<
            StandardErrorResponse<BasicErrorResponseType>,
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
            StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
            StandardRevocableToken,
            StandardErrorResponse<RevocationErrorResponseType>,
            EndpointSet,
            EndpointNotSet,
            EndpointNotSet,
            EndpointNotSet,
            EndpointSet,
        >,
    >,
) -> impl IntoResponse {
    // 1. Generate your secure random state string
    let state_string = hex::encode(rand::random_iter().take(64).collect::<Vec<_>>());

    // 2. Build the cookie explicitly
    let state_cookie = Cookie::build(("oauth_state", state_string))
        .path("/")
        .http_only(true)
        .secure(true) // Ensure this is true if accessing over HTTPS/Tailscale
        .same_site(SameSite::Lax)
        // Set a short expiration! They only need 5 minutes to log in.
        .max_age(time::Duration::minutes(5))
        .build();

    // 3. Add the cookie to the jar (this handles the ChaCha20 encryption automatically)
    let updated_jar = jar.add(state_cookie);

    // 4. Return the updated jar AND the redirect
    let google_url = oauth_client.authorize_url(|| state_string);

    (updated_jar, Redirect::to(&google_url))
}
