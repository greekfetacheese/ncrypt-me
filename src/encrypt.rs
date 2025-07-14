use super::*;

use bincode::{config::standard, encode_to_vec};
use chacha20poly1305::{
   AeadCore, KeyInit, XChaCha20Poly1305,
   aead::{Aead, OsRng, Payload, generic_array::GenericArray, rand_core::RngCore},
};
use secure_types::SecureBytes;

/*
██████████████████████████████████████████████████████████████████████████████
█                                                                            █
█                           nCrypt File Format                               █
█                                                                            █
█    ┌───────────┬──────────────────┬──────────────────┬───────────────┐     █
█    │   Header  │ EncryptedInfo Len│  EncryptedInfo   │ Encrypted Data│     █
█    │  8 bytes  │     4 bytes      │  Dyn Size        │ Dyn Size      │     █
█    └───────────┴──────────────────┴──────────────────┴───────────────┘     █
█                                                                            █
█                                                                            █
██████████████████████████████████████████████████████████████████████████████
*/

/// File Header
pub const HEADER: &[u8; 8] = b"nCrypt1\0";

/// Encrypts the given data
///
/// ### Arguments
///
/// - `argon2` - The Argon2 instance to use for the password hashing
/// - `data` - The data to encrypt
/// - `credentials` - The credentials to use for encryption
pub fn encrypt_data(
   argon2: Argon2,
   data: SecureBytes,
   credentials: Credentials,
) -> Result<Vec<u8>, Error> {
   let (encrypted_data, info) = encrypt(argon2, credentials, data)?;

   let encoded_info =
      encode_to_vec(&info, standard()).map_err(|e| Error::EncodingFailed(e.to_string()))?;

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
   argon2: Argon2,
   credentials: Credentials,
   data: SecureBytes,
) -> Result<(Vec<u8>, EncryptedInfo), Error> {
   credentials
      .is_valid()
      .map_err(|e| Error::InvalidCredentials(e.to_string()))?;

   if argon2.hash_length < 32 {
      return Err(Error::HashLength);
   }

   let mut password_salt = vec![0u8; RECOMMENDED_SALT_LEN];
   let mut username_salt = vec![0u8; RECOMMENDED_SALT_LEN];
   
   OsRng
      .try_fill_bytes(&mut password_salt)
      .map_err(|e| Error::Custom(e.to_string()))?;
   OsRng
      .try_fill_bytes(&mut username_salt)
      .map_err(|e| Error::Custom(e.to_string()))?;

   let cipher_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

   let password_hash = argon2.hash_password(&credentials.password, password_salt.clone())?;
   let username_hash = argon2.hash_password(&credentials.username, username_salt.clone())?;

   data.slice_scope(|data| {
      let mut aad = username_hash.slice_scope(|bytes| bytes.to_vec());

      let payload = Payload {
         msg: data,
         aad: &aad,
      };

      let cipher = xchacha20_poly_1305(password_hash);

      let encrypted_data_res = cipher.encrypt(&cipher_nonce, payload);
      aad.zeroize();

      let encrypted_data = match encrypted_data_res {
         Ok(data) => data,
         Err(e) => {
            return Err(Error::EncryptionFailed(e.to_string()));
         }
      };

      let info = EncryptedInfo::new(
         password_salt,
         username_salt,
         cipher_nonce.to_vec(),
         argon2,
      );

      Ok((encrypted_data, info))
   })
}

pub(crate) fn xchacha20_poly_1305(hash_output: SecureBytes) -> XChaCha20Poly1305 {
   let mut key = hash_output.slice_scope(|bytes| *GenericArray::from_slice(&bytes[..32]));

   let cipher = XChaCha20Poly1305::new(&key);
   key.zeroize();
   cipher
}
