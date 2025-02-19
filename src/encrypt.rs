use argon2::{
    password_hash::{ Output, PasswordHasher, SaltString },
    Algorithm,
    Argon2,
    Params,
    Version,
};
use chacha20poly1305::{
    aead::{ generic_array::GenericArray, Aead, OsRng, Payload },
    AeadCore,
    KeyInit,
    XChaCha20Poly1305,
};

use super::credentials::Credentials;
use super::error::Error;
use super::{ erase_output, Argon2Params, EncryptedInfo };
use bincode;

/*
██████████████████████████████████████████████████████████████████████████████
█                                                                            █
█                           nCrypt File Format                               █
█                                                                            █
█    ┌───────────┬──────────────────┬──────────────────┬───────────────┐     █
█    │   Header  │ EncryptedInfo Len│  EncryptedInfo   │ Encrypted Data│     █
█    │  8 bytes  │     4 bytes      │  Variable Size   │ Variable Size │     █
█    └───────────┴──────────────────┴──────────────────┴───────────────┘     █
█                                                                            █
█                                                                            █
██████████████████████████████████████████████████████████████████████████████
*/

/// File Header
pub const HEADER: &[u8; 8] = b"nCrypt1\0";

/// Encrypts the given data using the provided credentials
///
/// ### Arguments
///
/// - `argon_params` - The Argon2 parameters to use for the password hashing
/// - `data` - The data to encrypt
/// - `credentials` - The credentials to use for encryption
pub fn encrypt_data(
    argon_params: Argon2Params,
    data: Vec<u8>,
    credentials: Credentials
) -> Result<Vec<u8>, Error> {
    let (encrypted_data, info) = encrypt(argon_params, credentials, data)?;

    let serialized_info = bincode
        ::serialize(&info)
        .map_err(|e| Error::SerializationFailed(e.to_string()))?;

    // Construct the file format
    let mut result = Vec::new();

    // Append the header
    result.extend_from_slice(HEADER);

    // Append the EncryptedInfo Length
    let info_length = serialized_info.len() as u32;
    result.extend_from_slice(&info_length.to_le_bytes());

    // Append the EncryptedInfo
    result.extend_from_slice(&serialized_info);

    // Append the encrypted Data
    result.extend_from_slice(&encrypted_data);

    Ok(result)
}

fn encrypt(
    argon_params: Argon2Params,
    mut credentials: Credentials,
    data: Vec<u8>
) -> Result<(Vec<u8>, EncryptedInfo), Error> {
    credentials.is_valid().map_err(|e| Error::InvalidCredentials(e.to_string()))?;

    if argon_params.hash_length < 32 {
        return Err(Error::HashLength);
    }

    let params = Params::new(
        argon_params.m_cost,
        argon_params.t_cost,
        argon_params.p_cost,
        Some(argon_params.hash_length as usize)
    ).map_err(|e| Error::InvalidArgon2Params(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::default(), Version::default(), params);

    let password_salt = SaltString::generate(&mut OsRng);
    let username_salt = SaltString::generate(&mut OsRng);

    // hash the password
    let password_hash = argon2
        .hash_password(credentials.password().as_bytes(), &password_salt)
        .map_err(|e| Error::PasswordHashingFailed(e.to_string()))?;

    // get the hash output
    let mut key = password_hash.hash.ok_or(Error::PasswordHashOutput)?;

    // hash the username for the AAD
    let username_hash = argon2
        .hash_password(credentials.username().as_bytes(), &username_salt)
        .map_err(|e| Error::UsernameHashingFailed(e.to_string()))?;

    credentials.erase();

    let mut aad = username_hash.hash.ok_or(Error::UsernameHashOutput)?;

    // derive the cipher using the hashed password's last 32 bytes as the key
    let cipher = xchacha20_poly_1305(&key);
    let cipher_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    erase_output(&mut key);

    let payload = Payload {
        msg: data.as_ref(),
        aad: &aad.as_bytes(),
    };

    let encrypted_data = cipher
        .encrypt(&cipher_nonce, payload)
        .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

    erase_output(&mut aad);

    let info = EncryptedInfo::new(
        password_salt.to_string(),
        username_salt.to_string(),
        cipher_nonce.to_vec(),
        argon_params
    );

    Ok((encrypted_data, info))
}

pub fn xchacha20_poly_1305(key: &Output) -> XChaCha20Poly1305 {
    let key = GenericArray::from_slice(&key.as_bytes()[..32]);
    XChaCha20Poly1305::new(key)
}
