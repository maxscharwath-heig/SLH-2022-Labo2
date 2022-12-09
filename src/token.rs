pub mod token {
    use std::env;

    use axum_sessions::async_session::chrono::Utc;
    use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
    use serde::{Deserialize, Serialize};

    use crate::user::UserDTO;

    #[derive(Debug,Serialize, Deserialize)]
    struct Claims {
        sub: UserDTO,
        exp: usize,
    }

    pub fn decode_jwt(token: &str) -> jsonwebtoken::errors::Result<UserDTO> {
        let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        return jsonwebtoken::decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::default(),
        ).map(|data: TokenData<Claims>| data.claims.sub);
    }

    pub fn generate_jwt(sub: UserDTO) -> jsonwebtoken::errors::Result<String> {
        let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let exp = (Utc::now().timestamp() + 3600) as usize;
        return jsonwebtoken::encode(
            &Header::default(),
            &Claims {
                sub,
                exp,
            },
            &EncodingKey::from_secret(secret.as_ref()),
        );
    }
}
