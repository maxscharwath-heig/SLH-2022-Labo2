pub mod hash {
    use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
    use argon2::password_hash::rand_core::OsRng;
    use argon2::password_hash::SaltString;

    pub fn verify_password(password: &str, hash: &str) -> bool {
        let hash = PasswordHash::new(hash).unwrap();
        let argon2 = Argon2::default();
        argon2.verify_password(password.as_bytes(), &hash).is_ok()
    }

    pub fn password_hash(password: &str) -> String {
        let hasher = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let hash = hasher
            .hash_password(password.as_bytes(), &salt)
            .unwrap();
        hash.to_string()
    }
}
