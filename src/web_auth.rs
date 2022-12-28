use crate::db::{get_user, save_user, update_password, user_exists, verify_user, DbConn};
use crate::email::send_email;
use crate::hash::hash;
use crate::models::{
    AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest,
    VerifyEmailRequest, VerifyJwtToken,
};
use crate::oauth;
use crate::token::token;
use crate::user::{AuthenticationMethod, User, UserDTO};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::async_session::log::info;
use axum_sessions::async_session::{MemoryStore, Session, SessionStore};
use lettre::message::{header, MultiPart, SinglePart};
use lettre::Message;
use maud::html;
use oauth2::reqwest::{async_http_client, http_client};
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope};
use serde_json::json;
use std::env;
use std::error::Error;

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
    mut _conn: DbConn,
    jar: CookieJar,
    Json(login): Json<LoginRequest>,
) -> Result<(CookieJar, AuthResult), Response> {
    let _email = login.login_email;
    let _password = login.login_password;

    return match get_user(&mut _conn, &_email) {
        Ok(user) => {
            if hash::verify_password(&_password, &user.password) && user.email_verified {
                let jar = add_auth_cookie(jar, user.to_dto())
                    .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
                Ok((jar, AuthResult::Success))
            } else {
                Err(StatusCode::UNAUTHORIZED.into_response())
            }
        }
        Err(_) => {
            // fake hash to prevent timing attacks
            hash::verify_password(&_password, &_password);
            Err(StatusCode::UNAUTHORIZED.into_response())
        }
    };

    // Once the user has been created, authenticate the user by adding a JWT cookie in the cookie jar
    // let jar = add_auth_cookie(jar, &user_dto)
    //     .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
    //return Ok((jar, AuthResult::Success));
}

/// Endpoint used to register a new account
/// POST /register
/// BODY { "register_email": "email", "register_password": "password", "register_password2": "password" }
async fn register(
    mut _conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Json(register): Json<RegisterRequest>,
) -> Result<AuthResult, Response> {
    let _email = register.register_email;
    let _password = register.register_password;
    let _password2 = register.register_password2;

    if _password != _password2 {
        return Err(StatusCode::BAD_REQUEST.into_response());
    }

    let _hashed_password = hash::password_hash(&_password);

    return match user_exists(&mut _conn, &_email) {
        Ok(_) => Err("User already exists".into_response()),
        Err(_) => {
            let user = User::new(
                &_email,
                &_hashed_password,
                AuthenticationMethod::Password,
                false,
            );
            match save_user(&mut _conn, user) {
                Ok(_) => {
                    send_verification_email(&_email);
                    Ok(AuthResult::Success)
                }
                Err(e) => {
                    println!("Error: {}", e);
                    Err("Error".into_response())
                }
            }
        }
    };

    // Once the user has been created, send a verification link by email
    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.

    //Ok(AuthResult::Success)
}

fn send_verification_email(_email: &str) {
    let _token = token::generate_jwt(
        VerifyJwtToken {
            email: _email.to_string(),
        },
        10 * 60,
    )
    .expect("Failed to generate token");
    let _url = format!(
        "{}/verify?token={}",
        env::var("APP_URL").expect("APP_URL must be set"),
        _token
    );

    println!("Verification URL: {}", _url);

    let html = html! {
        div {
            h1 { "Verify your email" }
            p { "Please click the link below to verify your email" }
            a href=(_url) { (_url) }
        }
    };
    let message = Message::builder()
        .from("SLH Labs <sdr@heig-vd.ch>".parse().unwrap())
        .to(_email.parse().unwrap())
        .subject("Verify your email")
        .multipart(
            MultiPart::alternative() // This is composed of two parts.
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(format!(
                            "Please click the link below to verify your email: {}",
                            _url
                        )),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(html.into_string()),
                ),
        )
        .expect("failed to build email");
    send_email(&message);
}

async fn verify_email(
    mut _conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Query(_query): Query<VerifyEmailRequest>,
) -> Result<Redirect, Response> {
    let _email = token::decode_jwt::<VerifyJwtToken>(&_query.token)
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?
        .email;
    info!("Email: {}", _email);
    if user_exists(&mut _conn, &_email).is_ok() && verify_user(&mut _conn, &_email).is_ok() {
        info!("User verified");
        return Ok(Redirect::temporary("/login"));
    }
    return Ok(Redirect::temporary("/login"));
}

/// Endpoint used for the first OAuth step
/// GET /oauth/google
async fn google_oauth(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: This function is used to authenticate a user with Google's OAuth2 service.
    //       We want to use a PKCE authentication flow, you will have to generate a
    //       random challenge and a CSRF token. In order to get the email address of
    //       the user, use the following scope: https://www.googleapis.com/auth/userinfo.email
    //       Use Redirect::to(url) to redirect the user to Google's authentication form.

    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state) = oauth::OAUTH_CLIENT
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the "calendar" features and the user's profile.
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
        .expect("TODO: panic message");
    session
        .insert("csrf_state", csrf_state.secret().to_string())
        .expect("TODO: panic message");
    let store_cookie = _session_store
        .store_session(session)
        .await
        .unwrap()
        .unwrap();
    println!("store_cookie: {:?}", store_cookie);

    let cookie = Cookie::build("session", store_cookie)
        .path("/")
        .http_only(true)
        .finish();

    Ok((jar.add(cookie), Redirect::to(authorize_url.as_ref())))
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
    _conn: DbConn,
    _params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: The user should be redirected to this page automatically after a successful login.
    //       You will need to verify the CSRF token and ensure the authorization code is valid
    //       by interacting with Google's OAuth2 API (use an async request!). Once everything
    //       was verified, get the email address with the provided function (get_oauth_email)
    //       and create a JWT for the user.

    // If you need to recover data between requests, you may use the session_store to load a session
    // based on a session_id.

    // Once the OAuth user is authenticated, create the user in the DB and add a JWT cookie
    // let jar = add_auth_cookie(jar, &user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let code = AuthorizationCode::new(_params.code.clone());
    let state = CsrfToken::new(_params.state.clone());

    let session = _session_store
        .load_session(jar.get("session").unwrap().value().to_string())
        .await
        .unwrap()
        .unwrap();
    let pkce_code_verifier =
        PkceCodeVerifier::new(session.get::<String>("pkce_code_verifier").unwrap());
    let csrf_state = CsrfToken::new(session.get::<String>("csrf_state").unwrap().to_string());

    println!("Google returned the following code:\n{}\n", code.secret());
    println!(
        "Google returned the following state:\n{} (expected `{}`)\n",
        state.secret(),
        csrf_state.secret()
    );

    let token = oauth::OAUTH_CLIENT
        .exchange_code(code)
        .set_pkce_verifier(pkce_code_verifier)
        .request_async(async_http_client)
    .await
    .unwrap();

    let email = oauth::get_google_oauth_email(&token)
        .await
        .expect("Failed to get email");

    let user_dto = UserDTO {
        email,
        auth_method: AuthenticationMethod::OAuth,
    };

    let jar = add_auth_cookie(jar, user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok((jar, Redirect::to("/home")))
}

/// Endpoint handling login
/// POST /password_update
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    mut _conn: DbConn,
    _user: UserDTO,
    Json(_update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {
    if _update.old_password == _update.new_password {
        return Ok(AuthResult::Error(
            "New password must be different from old password".to_string(),
        ));
    }
    // check if old password is correct
    match get_user(&mut _conn, &_user.email) {
        Ok(user) => {
            if hash::verify_password(&_update.old_password, &user.password) {
                let _hashed_password = hash::password_hash(&_update.new_password);
                match update_password(&mut _conn, &_user.email, &_hashed_password) {
                    Ok(_) => {
                        info!("Password updated");
                        let html = html! {
                            div {
                                h1 { "Password updated" }
                                p { "This email is to confirm that your password has been updated." }
                                p { "If you did not request this change, please contact us immediately." }
                            }
                        };

                        let message = Message::builder()
                            .from("SLH Labs <sdr@heig-vd.ch>".parse().unwrap())
                            .to(_user.email.parse().unwrap())
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
                                            .body(html.into_string()),
                                    ),
                            )
                            .expect("failed to build email");
                        send_email(&message);

                        Ok(AuthResult::Success)
                    }
                    Err(_) => Ok(AuthResult::Error("Failed to update password".to_string())),
                }
            } else {
                Ok(AuthResult::Error("Old password is incorrect".to_string()))
            }
        }
        _ => Ok(AuthResult::Error("Failed to get user".to_string())),
    }
}

/// Endpoint handling the logout logic
/// GET /logout
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let new_jar = jar.remove(Cookie::named("auth"));
    (new_jar, Redirect::to("/home"))
}

#[allow(dead_code)]
fn add_auth_cookie(jar: CookieJar, _user: UserDTO) -> Result<CookieJar, Box<dyn Error>> {
    let jwt = token::generate_jwt(_user, 3600)?;
    let cookie = Cookie::build("auth", jwt)
        .path("/")
        .secure(true)
        .http_only(true)
        .finish();
    Ok(jar.add(cookie))
}

enum AuthResult {
    Success,
    Error(String),
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, "Success".to_string()),
            Self::Error(message) => (StatusCode::BAD_REQUEST, message),
        };
        (status, Json(json!({ "res": message }))).into_response()
    }
}
