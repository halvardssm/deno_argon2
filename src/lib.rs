use wasm_bindgen::prelude::*;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Version,
};

#[wasm_bindgen]
pub enum Algorithm {
    /// Optimizes against GPU cracking attacks but vulnerable to side-channels.
    ///
    /// Accesses the memory array in a password dependent order, reducing the
    /// possibility of time–memory tradeoff (TMTO) attacks.
    Argon2d = 0,

    /// Optimized to resist side-channel attacks.
    ///
    /// Accesses the memory array in a password independent order, increasing the
    /// possibility of time-memory tradeoff (TMTO) attacks.
    Argon2i = 1,

    /// Hybrid that mixes Argon2i and Argon2d passes (*default*).
    ///
    /// Uses the Argon2i approach for the first half pass over memory and
    /// Argon2d approach for subsequent passes. This effectively places it in
    /// the "middle" between the other two: it doesn't provide as good
    /// TMTO/GPU cracking resistance as Argon2d, nor as good of side-channel
    /// resistance as Argon2i, but overall provides the most well-rounded
    /// approach to both classes of attacks.
    Argon2id = 2,
}

impl Default for Algorithm {
    fn default() -> Algorithm {
        Algorithm::Argon2id
    }
}

#[wasm_bindgen]
pub struct Params {
    /// Memory size, expressed in kilobytes, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    memory_cost: u32,

    /// Number of iterations, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    time_cost: u32,

    /// Degree of parallelism, between 1 and 255.
    ///
    /// Value is an integer in decimal (1 to 3 digits).
    parallelism_cost: u32,

    /// Size of the output (in bytes).
    output_length: Option<usize>,
}

#[wasm_bindgen]
pub fn hash(password: &str, algo: Option<Algorithm>, params: Option<Params>) -> String {
    let algorithm = match algo.unwrap_or_default() {
        Algorithm::Argon2d => argon2::Algorithm::Argon2d,
        Algorithm::Argon2i => argon2::Algorithm::Argon2i,
        Algorithm::Argon2id => argon2::Algorithm::Argon2id,
    };

    let mut _params: argon2::Params;
    if params.is_none() {
        _params = argon2::Params::default();
    } else {
        let unwrapped_params = params.unwrap();
        _params = argon2::Params::new(
            unwrapped_params.memory_cost,
            unwrapped_params.time_cost,
            unwrapped_params.parallelism_cost,
            unwrapped_params.output_length,
        )
        .expect("bad argon2 parameters");
    }

    let argon2 = Argon2::new(algorithm, Version::V0x13, _params);
    let salt = SaltString::generate(&mut OsRng);
    let password_bytes = password.as_bytes();
    argon2
        .hash_password(password_bytes, &salt)
        .expect("hashing failed")
        .to_string()
}

#[wasm_bindgen]
pub fn verify(password: &str, password_hash: &str) -> u8 {
    let password_bytes = password.as_bytes();
    let parsed_hash = PasswordHash::new(&password_hash).expect("failed to parse hash");
    let success = Argon2::default()
        .verify_password(password_bytes, &parsed_hash)
        .is_ok();
    match success {
        true => 1,
        false => 0,
    }
}
