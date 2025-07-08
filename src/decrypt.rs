use super::{
   EncryptedInfo, credentials::Credentials, encrypt::*, erase_output, error::Error,
   extract_encrypted_info_and_data,
};
use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};
use bincode::{config::legacy, decode_from_slice};
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

   let (encrypted_info, encrypted_data) = extract_encrypted_info_and_data(&data)?;

   let info: (EncryptedInfo, usize) = decode_from_slice(&encrypted_info, legacy())
      .map_err(|e| Error::DecodingFailed(e.to_string()))?;

   let decrypted_data = decrypt(credentials, info.0, encrypted_data)?;
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

   let decrypted_data_res = cipher.decrypt(nonce, payload);

   let decrypted_data = match decrypted_data_res {
      Ok(data) => data,
      Err(e) => {
         erase_output(&mut aad);
         return Err(Error::DecryptionFailed(e.to_string()));
      }
   };

   erase_output(&mut aad);

   let secure_data =
      SecureBytes::from_vec(decrypted_data).map_err(|e| Error::Custom(e.to_string()))?;

   Ok(secure_data)
}
