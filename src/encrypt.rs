use super::credentials::Credentials;
use super::error::Error;
use super::{Argon2Params, EncryptedInfo, erase_output};
use argon2::{
   Algorithm, Argon2, Params, Version,
   password_hash::{Output, PasswordHasher, SaltString},
};
use bincode::{config::legacy, encode_to_vec};
use chacha20poly1305::{
   AeadCore, KeyInit, XChaCha20Poly1305,
   aead::{Aead, OsRng, Payload, generic_array::GenericArray},
};
use secure_types::SecureBytes;

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
   data: SecureBytes,
   credentials: Credentials,
) -> Result<Vec<u8>, Error> {
   let (encrypted_data, info) = encrypt(argon_params, credentials, data)?;

   let encoded_info =
      encode_to_vec(&info, legacy()).map_err(|e| Error::EncodingFailed(e.to_string()))?;

   // Construct the file format
   let mut result = Vec::new();

   // Append the header
   result.extend_from_slice(HEADER);

   // Append the EncryptedInfo Length
   let info_length = encoded_info.len() as u32;
   result.extend_from_slice(&info_length.to_le_bytes());

   // Append the EncryptedInfo
   result.extend_from_slice(&encoded_info);

   // Append the encrypted Data
   result.extend_from_slice(&encrypted_data);

   Ok(result)
}

fn encrypt(
   argon_params: Argon2Params,
   mut credentials: Credentials,
   data: SecureBytes,
) -> Result<(Vec<u8>, EncryptedInfo), Error> {
   credentials
      .is_valid()
      .map_err(|e| Error::InvalidCredentials(e.to_string()))?;

   if argon_params.hash_length < 32 {
      return Err(Error::HashLength);
   }

   let params = Params::new(
      argon_params.m_cost,
      argon_params.t_cost,
      argon_params.p_cost,
      Some(argon_params.hash_length as usize),
   )
   .map_err(|e| Error::InvalidArgon2Params(e.to_string()))?;

   let argon2 = Argon2::new(Algorithm::default(), Version::default(), params);

   let password_salt = SaltString::generate(&mut OsRng);
   let username_salt = SaltString::generate(&mut OsRng);

   let cipher = derive_cipher(&credentials, &password_salt, argon2.clone())?;
   let mut aad = derive_aad(&credentials, &username_salt, argon2.clone())?;

   credentials.erase();

   let cipher_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

   data.slice_scope(|data| {
      let payload = Payload {
         msg: data,
         aad: &aad.as_bytes(),
      };

      let encrypted_data_res = cipher.encrypt(&cipher_nonce, payload);

      let encrypted_data = match encrypted_data_res {
         Ok(data) => data,
         Err(e) => {
            erase_output(&mut aad);
            return Err(Error::EncryptionFailed(e.to_string()));
         }
      };

      erase_output(&mut aad);

      let info = EncryptedInfo::new(
         password_salt.to_string(),
         username_salt.to_string(),
         cipher_nonce.to_vec(),
         argon_params,
      );

      Ok((encrypted_data, info))
   })
}

pub(crate) fn derive_cipher(
   credentials: &Credentials,
   password_salt: &SaltString,
   argon2: Argon2,
) -> Result<XChaCha20Poly1305, Error> {
   credentials.password.str_scope(|password| {
      let password_hash = argon2
         .hash_password(password.as_bytes(), password_salt)
         .map_err(|e| Error::PasswordHashingFailed(e.to_string()))?;

      let mut key = password_hash.hash.ok_or(Error::PasswordHashOutput)?;

      let cipher = xchacha20_poly_1305(&key);
      erase_output(&mut key);
      Ok(cipher)
   })
}

pub(crate) fn derive_aad(
   credentials: &Credentials,
   username_salt: &SaltString,
   argon2: Argon2,
) -> Result<Output, Error> {
   credentials.username.str_scope(|username| {
      let username_hash = argon2
         .hash_password(username.as_bytes(), username_salt)
         .map_err(|e| Error::UsernameHashingFailed(e.to_string()))?;
      Ok(username_hash.hash.ok_or(Error::UsernameHashOutput)?)
   })
}

pub(crate) fn xchacha20_poly_1305(key: &Output) -> XChaCha20Poly1305 {
   let key = GenericArray::from_slice(&key.as_bytes()[..32]);
   XChaCha20Poly1305::new(key)
}
