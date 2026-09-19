use super::{
   EncryptedInfo, credentials::Credentials, encrypt::*, error::Error,
   extract_encrypted_info_and_data,
};
use chacha20poly1305::aead::{Aead, Payload, generic_array::GenericArray};
use secure_types::{SecureBytes, Zeroize};

/// Decrypts the data using the provided credentials
///
/// ### Arguments
///
/// - `data` - The data to decrypt
/// - `credentials` - The credentials to use for decryption
pub fn decrypt_data(data: Vec<u8>, credentials: Credentials) -> Result<SecureBytes, Error> {
   let (_, encrypted_data) = extract_encrypted_info_and_data(&data)?;

   let info = EncryptedInfo::from_encrypted_data(&data)?;

   let decrypted_data = decrypt(credentials, info, encrypted_data)?;
   let secure_data =
      SecureBytes::from_vec(decrypted_data).map_err(|e| Error::Custom(e.to_string()))?;

   Ok(secure_data)
}

/// Decrypts the data using the provided credentials
///
/// This is the same as `decrypt_data` but returns an unsecure [Vec<u8>]
///
/// Use this if the data you want to decrypt is too large to fit in a [SecureBytes]
///
/// ### Arguments
///
/// - `data` - The data to decrypt
/// - `credentials` - The credentials to use for decryption
pub fn decrypt_data_unsecured(data: Vec<u8>, credentials: Credentials) -> Result<Vec<u8>, Error> {
   let (_, encrypted_data) = extract_encrypted_info_and_data(&data)?;

   let info = EncryptedInfo::from_encrypted_data(&data)?;

   let decrypted_data = decrypt(credentials, info, encrypted_data)?;
   Ok(decrypted_data)
}

fn decrypt(credentials: Credentials, info: EncryptedInfo, data: Vec<u8>) -> Result<Vec<u8>, Error> {
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

   Ok(decrypted_data)
}
