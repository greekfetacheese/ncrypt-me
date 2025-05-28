use super::{EncryptedInfo, credentials::Credentials, encrypt::*, erase_output, error::Error};
use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};
use chacha20poly1305::aead::{Aead, Payload, generic_array::GenericArray};
use secure_types::SecureBytes;

/// Decrypts the data using the provided credentials
///
/// ### Arguments
///
/// - `data` - The data to decrypt
/// - `credentials` - The credentials to use for decryption
pub fn decrypt_data(data: Vec<u8>, credentials: Credentials) -> Result<SecureBytes, Error> {
   // Verify Header
   if &data[0..8] != HEADER {
      return Err(Error::InvalidFileFormat);
   }

   // Read EncryptedInfo Length
   let info_length = u32::from_le_bytes(data[8..12].try_into().map_err(|_| Error::EncryptedInfo)?);

   // Extract EncryptedInfo
   let info_start = 12;
   let info_end = info_start + (info_length as usize);
   let info_bytes = &data[info_start..info_end];

   let info: EncryptedInfo =
      bincode::deserialize(info_bytes).map_err(|e| Error::DeserializationFailed(e.to_string()))?;

   // Extract Encrypted Data
   let encrypted_data = &data[info_end..];

   let decrypted_data = decrypt(credentials, info, encrypted_data.to_vec())?;
   Ok(decrypted_data)
}

fn decrypt(
   mut credentials: Credentials,
   info: EncryptedInfo,
   data: Vec<u8>,
) -> Result<SecureBytes, Error> {
   credentials
      .is_valid()
      .map_err(|e| Error::InvalidCredentials(e.to_string()))?;

   let params = Params::new(
      info.argon2_params.m_cost,
      info.argon2_params.t_cost,
      info.argon2_params.p_cost,
      Some(info.argon2_params.hash_length as usize),
   )
   .map_err(|e| Error::InvalidArgon2Params(e.to_string()))?;

   let argon2 = Argon2::new(
      Algorithm::default(),
      Version::default(),
      params.clone(),
   );

   let password_salt =
      SaltString::from_b64(&info.password_salt).map_err(|e| Error::PasswordSalt(e.to_string()))?;

   let username_salt =
      SaltString::from_b64(&info.username_salt).map_err(|e| Error::UsernameSalt(e.to_string()))?;

   let cipher = derive_cipher(&credentials, &password_salt, argon2.clone())?;
   let mut aad = derive_aad(&credentials, &username_salt, argon2.clone())?;

   credentials.erase();

   let payload = Payload {
      msg: data.as_ref(),
      aad: aad.as_bytes(),
   };

   let nonce = GenericArray::from_slice(&info.cipher_nonce);

   let decrypted_data = cipher
      .decrypt(nonce, payload)
      .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

   erase_output(&mut aad);

   Ok(SecureBytes::from_vec(decrypted_data))
}
