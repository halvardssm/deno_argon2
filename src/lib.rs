use wasm_bindgen::prelude::*;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Version,
};

#[wasm_bindgen]
#[derive(Copy, Clone)]
#[derive(Debug)]
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
#[derive(Default)]
#[derive(Debug)]
pub struct HashOptions {
    /// Argon2 alorithm to use, can be one of Argon2d, Argon2i, or Argon2id.
    /// Default is Argon2id.
    pub algorithm: Option<Algorithm>,
    /// Memory size, expressed in kilobytes, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    #[wasm_bindgen(js_name = memoryCost)]
    pub memory_cost: Option<u32>,
    
    /// Number of iterations, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    #[wasm_bindgen(js_name = timeCost)]
    pub time_cost: Option<u32>,
    
    /// Degree of parallelism, between 1 and 255.
    ///
    /// Value is an integer in decimal (1 to 3 digits).
    #[wasm_bindgen(js_name = parallelismCost)]
    pub parallelism_cost: Option<u32>,
    
    /// Size of the output (in bytes).
    #[wasm_bindgen(js_name = outputLength)]
    pub output_length: Option<usize>,
}

#[wasm_bindgen]
pub fn hash(password: &str, options: Option<HashOptions>) -> String {
    let opts = options.unwrap_or_default();
    println!("opts: {:?}", opts);
    
    let algorithm = match opts.algorithm.unwrap_or_default() {
        Algorithm::Argon2d => argon2::Algorithm::Argon2d,
        Algorithm::Argon2i => argon2::Algorithm::Argon2i,
        Algorithm::Argon2id => argon2::Algorithm::Argon2id,
    };
    println!("algorithm: {:?}", algorithm);
    
    let default_params = argon2::Params::default();
    println!("default_params: {:?}", default_params);

    let params = argon2::Params::new(
        opts.memory_cost.unwrap_or(default_params.m_cost()),
        opts.time_cost.unwrap_or(default_params.t_cost()),
        opts.parallelism_cost.unwrap_or(default_params.p_cost()),
        Some(opts.output_length.unwrap_or(default_params.output_len().unwrap_or_default()))
    ).expect("bad argon2 parameters");

    println!("params: {:?}", params);

    let argon2 = Argon2::new(algorithm, Version::V0x13, params);
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
