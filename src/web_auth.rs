use std::env;
use std::error::Error;

use axum::{Json, Router};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::async_session::{MemoryStore, Session, SessionStore};
use axum_sessions::async_session::log::info;
use handlebars::Handlebars;
use lettre::message::{header, MultiPart, SinglePart};
use lettre::Message;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope};
use oauth2::reqwest::async_http_client;
use serde_json::json;

use crate::db::{DbConn, get_user, save_user, update_password, user_exists, verify_user};
use crate::email::send_email;
use crate::hash::hash;
use crate::models::{
    AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest,
    VerifyEmailRequest, VerifyJwtToken,
};
use crate::oauth;
use crate::token::token;
use crate::user::{AuthenticationMethod, User, UserDTO};

/// Declares the different endpoints
/// state is used to pass common structs to the endpoints
pub fn stage(state: AppState) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/verify", get(verify_email))
        .route("/oauth/google", get(google_oauth))
        .route("/_oauth", get(oauth_redirect))
        .route("/password_update", post(password_update))
        .route("/logout", get(logout))
        .with_state(state)
}

/// Endpoint handling login
/// POST /login
/// BODY { "login_email": "email", "login_password": "password" }
async fn login(
    mut conn: DbConn,
    jar: CookieJar,
    Json(login): Json<LoginRequest>,
) -> Result<(CookieJar, AuthResult), Response> {
    let email = login.login_email;
    let password = login.login_password;

    return match get_user(&mut conn, &email) {
        Ok(user) => {
            if hash::verify_password(&password, &user.password)
                && user.email_verified
                && user.get_auth_method() == AuthenticationMethod::Password
            {
                let jar = add_auth_cookie(jar, user.to_dto())
                    .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
                Ok((jar, AuthResult::Success))
            } else {
                Ok((jar, AuthResult::Error(StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())))
            }
        }
        Err(_) => {
            // fake hash to prevent timing attacks
            hash::fake_verify_password(&password);
            Ok((jar, AuthResult::Error(StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())))
        }
    };
}

/// Endpoint used to register a new account
/// POST /register
/// BODY { "register_email": "email", "register_password": "password", "register_password2": "password" }
async fn register(
    mut conn: DbConn,
    State(hbs): State<Handlebars<'_>>,
    Json(register): Json<RegisterRequest>,
) -> Result<AuthResult, Response> {
    let email = register.register_email;
    let password = register.register_password;
    let password2 = register.register_password2;

    if password != password2 {
        return Ok(
            AuthResult::Error(
                StatusCode::BAD_REQUEST,
                "Passwords do not match".to_string()
            ));
    }

    if !check_password(password.as_str()) {
        return Ok(AuthResult::Error(
            StatusCode::BAD_REQUEST,
            "Password is not strong enough".to_string(),
        ));
    }

    let hashed_password = hash::password_hash(&password);

    return match user_exists(&mut conn, &email) {
        Ok(_) => Err("User already exists".into_response()),
        Err(_) => {
            let user = User::new(
                &email,
                &hashed_password,
                AuthenticationMethod::Password,
                false,
            );
            match save_user(&mut conn, user) {
                Ok(_) => {
                    send_verification_email(&email, &hbs);
                    Ok(AuthResult::Success)
                }
                Err(e) => {
                    Err("Error".into_response())
                }
            }
        }
    };
}

fn check_password(password: &str) -> bool {
    let password_strength = zxcvbn::zxcvbn(&password, &[]).unwrap();
    return password.chars().count() >= 8 && password.chars().count() <= 64 && password_strength.score() >= 3;
}

fn send_verification_email(email: &str, hbs: &Handlebars<'_>) {
    let token = token::generate_jwt(
        VerifyJwtToken {
            email: email.to_string(),
        },
        10 * 60,
        "verify",
    )
    .expect("Failed to generate token");
    let url = format!(
        "{}/verify?token={}",
        env::var("APP_URL").expect("APP_URL must be set"),
        token
    );

    let html = hbs
        .render(
            "email_verify",
            &json!({
                "url": url,
                "email": email
            }),
        )
        .unwrap();

    let message = Message::builder()
        .from("SLH Labs <sdr@heig-vd.ch>".parse().unwrap())
        .to(email.parse().unwrap())
        .subject("Verify your email")
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(format!(
                            "Please click the link below to verify your email: {}",
                            url
                        )),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(html),
                ),
        )
        .expect("failed to build email");
    send_email(&message);
}

async fn verify_email(
    mut conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Query(query): Query<VerifyEmailRequest>,
) -> Result<Redirect, Response> {
    let email = token::decode_jwt::<VerifyJwtToken>(&query.token, "verify")
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?
        .email;
    if user_exists(&mut conn, &email).is_ok() && verify_user(&mut conn, &email).is_ok() {
        return Ok(Redirect::temporary("/login"));
    }
    return Ok(Redirect::temporary("/login"));
}

/// Endpoint used for the first OAuth step
/// GET /oauth/google
async fn google_oauth(
    jar: CookieJar,
    State(session_store): State<MemoryStore>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state) = oauth::OAUTH_CLIENT
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.email".to_string(),
        ))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    let mut session = Session::new();
    session
        .insert(
            "pkce_code_verifier",
            pkce_code_verifier.secret().to_string(),
        )
        .unwrap();
    session
        .insert("csrf_state", csrf_state.secret().to_string())
        .unwrap();

    let store_cookie = session_store.store_session(session).await.unwrap().unwrap();

    let cookie = Cookie::build("session", store_cookie)
        .path("/")
        .secure(true)
        .http_only(true)
        .finish();

    Ok((jar.add(cookie), Redirect::to(authorize_url.as_ref())))
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    jar: CookieJar,
    State(session_store): State<MemoryStore>,
    mut conn: DbConn,
    params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let code = AuthorizationCode::new(params.code.clone());
    let state = CsrfToken::new(params.state.clone());

    let session = session_store
        .load_session(jar.get("session").unwrap().value().to_string())
        .await
        .unwrap()
        .unwrap();

    let pkce_code_verifier =
        PkceCodeVerifier::new(session.get::<String>("pkce_code_verifier").unwrap());
    let csrf_state = CsrfToken::new(session.get::<String>("csrf_state").unwrap().to_string());

    if csrf_state.secret() != state.secret() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let token = oauth::OAUTH_CLIENT
        .exchange_code(code)
        .set_pkce_verifier(pkce_code_verifier)
        .request_async(async_http_client)
        .await
        .unwrap();

    let email = oauth::get_google_oauth_email(&token).await.unwrap();

    let user = match get_user(&mut conn, &email) {
        Err(_) => {
            let user = User::new(&email, "", AuthenticationMethod::OAuth, true);
            save_user(&mut conn, user).unwrap();
            get_user(&mut conn, &email).unwrap()
        }
        Ok(user) => user,
    };

    // accept only verified users and users with Google authentication
    if !user.email_verified || user.get_auth_method() != AuthenticationMethod::OAuth {
        return Ok((jar, Redirect::to("/login")));
    }

    let jar = add_auth_cookie(jar, user.to_dto()).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok((jar, Redirect::to("/home")))
}

/// Endpoint handling login
/// POST /password_update
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    State(hbs): State<Handlebars<'_>>,
    mut conn: DbConn,
    user: UserDTO,
    Json(update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {
    if user.auth_method != AuthenticationMethod::Password {
        // only password users can update their password
        return Err(StatusCode::UNAUTHORIZED.into_response());
    }

    if update.old_password == update.new_password {
        return Ok(AuthResult::Error(
            StatusCode::BAD_REQUEST,
            "New password must be different from old password".to_string(),
        ));
    }

    if !check_password(update.new_password.as_str()){
        return Ok(AuthResult::Error(
            StatusCode::BAD_REQUEST,
            "Password is not strong enough".to_string(),
        ));
    }

    // check if old password is correct
    match get_user(&mut conn, &user.email) {
        Ok(user) => {
            if hash::verify_password(&update.old_password, &user.password) {
                let _hashed_password = hash::password_hash(&update.new_password);
                match update_password(&mut conn, &user.email, &_hashed_password) {
                    Ok(_) => {
                        let html = hbs
                            .render(
                                "password_updated",
                                &json!({
                                    "email": user.email,
                                }),
                            )
                            .unwrap();

                        let message = Message::builder()
                            .from("SLH Labs <sdr@heig-vd.ch>".parse().unwrap())
                            .to(user.email.parse().unwrap())
                            .subject("Password updated")
                            .multipart(
                                MultiPart::alternative() // This is composed of two parts.
                                    .singlepart(
                                        SinglePart::builder()
                                            .header(header::ContentType::TEXT_PLAIN)
                                            .body(format!("This email is to confirm that your password has been updated. If you did not request this change, please contact us immediately.")),
                                    )
                                    .singlepart(
                                        SinglePart::builder()
                                            .header(header::ContentType::TEXT_HTML)
                                            .body(html),
                                    ),
                            )
                            .expect("failed to build email");
                        send_email(&message);

                        Ok(AuthResult::Success)
                    }
                    Err(_) => Ok(AuthResult::Error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to update password".to_string(),
                    )),
                }
            } else {
                Ok(AuthResult::Error(
                    StatusCode::BAD_REQUEST,
                    "Old password is incorrect".to_string(),
                ))
            }
        }
        _ => Ok(AuthResult::Error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update password".to_string(),
        )),
    }
}

/// Endpoint handling the logout logic
/// GET /logout
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let new_jar = jar.remove(Cookie::named("auth"));
    (new_jar, Redirect::to("/home"))
}

#[allow(dead_code)]
fn add_auth_cookie(jar: CookieJar, user: UserDTO) -> Result<CookieJar, Box<dyn Error>> {
    let jwt = token::generate_jwt(user, 3600, "auth")?;
    let cookie = Cookie::build("auth", jwt)
        .path("/")
        .secure(true)
        .http_only(true)
        .finish();
    Ok(jar.add(cookie))
}

enum AuthResult {
    Success,
    Error(StatusCode, String),
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, "Success".to_string()),
            Self::Error(status, message) => (status, message),
        };
        (status, Json(json!({ "res": message }))).into_response()
    }
}
