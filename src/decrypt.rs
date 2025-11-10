use super::{
   EncryptedInfo, credentials::Credentials, encrypt::*, error::Error,
   extract_encrypted_info_and_data,
};
use bincode::{config::standard, decode_from_slice};
use chacha20poly1305::aead::{Aead, Payload, generic_array::GenericArray};
use secure_types::SecureBytes;
use zeroize::Zeroize;

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

   let info: (EncryptedInfo, usize) = decode_from_slice(&encrypted_info, standard())
      .map_err(|e| Error::DecodingFailed(e.to_string()))?;

   let decrypted_data = decrypt(credentials, info.0, encrypted_data)?;
   Ok(decrypted_data)
}

fn decrypt(
   credentials: Credentials,
   info: EncryptedInfo,
   data: Vec<u8>,
) -> Result<SecureBytes, Error> {
   credentials.is_valid()?;

   let argon2 = &info.argon2;
   let username = &credentials.username;
   let password = &credentials.password;

   let mut aad = username
      .unlock_str(|username_str| argon2.hash_password(&username_str, info.username_salt.clone()))
      .map_err(|e| Error::Custom(e.to_string()))?;

   let password_hash = password
      .unlock_str(|password_str| argon2.hash_password(&password_str, info.password_salt.clone()))
      .map_err(|e| Error::Custom(e.to_string()))?;

   let nonce = GenericArray::from_slice(&info.cipher_nonce);

   let payload = Payload {
      msg: data.as_ref(),
      aad: &aad,
   };

   let cipher = xchacha20_poly_1305(password_hash);
   let decrypted_data_res = cipher.decrypt(nonce, payload);
   aad.zeroize();

   let decrypted_data = match decrypted_data_res {
      Ok(data) => data,
      Err(e) => {
         return Err(Error::DecryptionFailed(e.to_string()));
      }
   };

   let secure_data =
      SecureBytes::from_vec(decrypted_data).map_err(|e| Error::Custom(e.to_string()))?;

   Ok(secure_data)
}
