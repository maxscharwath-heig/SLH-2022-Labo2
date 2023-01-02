pub mod hash {
    use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
    use argon2::password_hash::rand_core::OsRng;
    use argon2::password_hash::SaltString;
    use once_cell::sync::Lazy;

    static FAKE_HASH: Lazy<PasswordHash> = Lazy::new(|| {
        static SALT: Lazy<SaltString> = Lazy::new(|| SaltString::generate(&mut OsRng));
        let argon2 = Argon2::default();
        argon2.hash_password(b"fake_password", SALT.as_ref()).unwrap()
    });

    pub fn verify_password(password: &str, hash: &str) -> bool {
        let argon2 = Argon2::default();
        match  PasswordHash::new(hash) {
            Ok(hash) => argon2.verify_password(password.as_bytes(), &hash).is_ok(),
            _ => false
        }
    }

    pub fn fake_verify_password(password: &str) {
        let argon2 = Argon2::default();
        let _ = argon2.verify_password(password.as_bytes(), &FAKE_HASH).is_ok();
    }

    pub fn password_hash(password: &str) -> String {
        let hasher = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let hash = hasher.hash_password(password.as_bytes(), &salt).unwrap();
        hash.to_string()
    }
}
