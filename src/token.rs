pub mod token {
    use std::env;

    use axum_sessions::async_session::chrono::Utc;
    use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
    use serde::{Deserialize, Serialize};
    use serde::de::DeserializeOwned;

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims<T> {
        data: T,
        exp: usize,
    }

    pub fn decode_jwt<T: DeserializeOwned>(token: &str) -> jsonwebtoken::errors::Result<T> {
        let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        return jsonwebtoken::decode::<Claims<T>>(
            &token,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::default(),
        )
        .map(|data: TokenData<Claims<T>>| data.claims.data);
    }

    pub fn generate_jwt<T: Serialize>(data: T, ttl: usize) -> jsonwebtoken::errors::Result<String> {
        let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let exp = Utc::now().timestamp() as usize + ttl;
        return jsonwebtoken::encode(
            &Header::default(),
            &Claims { data, exp },
            &EncodingKey::from_secret(secret.as_ref()),
        );
    }
}
