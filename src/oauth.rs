use std::env;

use oauth2::{
    AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenResponse, TokenUrl,
};
use oauth2::basic::{BasicClient, BasicTokenResponse};
use once_cell::sync::Lazy;
use reqwest::{StatusCode};
use serde::{Deserialize, Serialize};

/// Lazy is used to initialize a complex static variable as it is currently not supported in native Rust.
/// The initialization is done only once when the variable is used for the first time.
pub static GOOGLE_OAUTH_CLIENT: Lazy<BasicClient> = Lazy::new(|| {
    let google_client_id =
        ClientId::new(env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set"));
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set"),
    );

    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");

    let redirect_url =
        RedirectUrl::new(env::var("OAUTH_CALLBACK_URL").expect("OAUTH_CALLBACK_URL must be set"))
            .expect("Invalid redirect URL");

    BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_url)
});


pub static GITHUB_OAUTH_CLIENT: Lazy<BasicClient> = Lazy::new(|| {
    let github_client_id =
        ClientId::new(env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID must be set"));
    let github_client_secret = ClientSecret::new(
        env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET must be set"),
    );

    let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
        .expect("Invalid authorization endpoint URL");

    let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
        .expect("Invalid token endpoint URL");

    let redirect_url =
        RedirectUrl::new(env::var("OAUTH_CALLBACK_URL").expect("OAUTH_CALLBACK_URL must be set"))
            .expect("Invalid redirect URL");

    BasicClient::new(
        github_client_id,
        Some(github_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_url)
});


static REQW_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| reqwest::Client::new());

/// Structure returned by Google API when requesting the email address
#[derive(Serialize, Deserialize, Debug)]
struct GoogleUserInfoEmail {
    id: String,
    email: String,
    verified_email: bool,
    picture: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct GithubUserInfoEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// Returns the email address associated with the token
pub async fn get_google_oauth_email(token: &BasicTokenResponse) -> Result<String, StatusCode> {
    REQW_CLIENT
        .get("https://www.googleapis.com/oauth2/v1/userinfo")
        .query(&[("access_token", token.access_token().secret())])
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .send()
        .await
        .and_then(|r| Ok(r.json::<GoogleUserInfoEmail>()))
        .or_else(|_| Err(StatusCode::UNAUTHORIZED))?
        .await
        .and_then(|user_info| Ok(user_info.email))
        .or_else(|_| Err(StatusCode::UNAUTHORIZED))
}

pub async fn get_github_oauth_email(token: &BasicTokenResponse) -> Result<String, StatusCode> {
    let token = token.access_token().secret();
    REQW_CLIENT
        .get("https://api.github.com/user/emails")
        .header(reqwest::header::CONTENT_TYPE, "application/vnd.github+json")
        .header(reqwest::header::USER_AGENT, "rust")
        .bearer_auth(token)
        .send()
        .await
        .and_then(|r| Ok(r.json::<Vec<GithubUserInfoEmail>>()))
        .or_else(|_| Err(StatusCode::UNAUTHORIZED))?
        .await
        .and_then(|user_info| {
            let email = user_info
                .into_iter()
                .find(|email| email.primary && email.verified)
                .map(|email| email.email);
            return Ok(email);
        })
        .or_else(|_| Err(StatusCode::UNAUTHORIZED))
        .and_then(|email| {
            email.ok_or(StatusCode::UNAUTHORIZED)
        })
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum OAuthProvider {
    Google,
    Github,
}

impl OAuthProvider {
    pub fn get_client(&self) -> &BasicClient {
        match self {
            OAuthProvider::Google => &GOOGLE_OAUTH_CLIENT,
            OAuthProvider::Github => &GITHUB_OAUTH_CLIENT,
        }
    }

    pub async fn get_email(&self, token: &BasicTokenResponse) -> Result<String, StatusCode> {
        match self {
            OAuthProvider::Google => get_google_oauth_email(token).await,
            OAuthProvider::Github => get_github_oauth_email(token).await,
        }
    }
}

