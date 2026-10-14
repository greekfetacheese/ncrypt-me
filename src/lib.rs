//! ncrypt_me - Secure Data Encryption
//!
//!
//! ## How the Data is Encrypted
//!
//! Given some `Credentials` (username and password):
//!
//! - **Hashing**: Both the password and username are hashed using **Argon2**.
//!   - The resulting hash of the **password** is used as the **key** for the **XChaCha20Poly1305** cipher.
//!   - The resulting hash of the **username** is used as the **Additional Authenticated Data (AAD)** for the cipher.
//!
//! - **Encryption**: With the key and AAD set, the data is encrypted using the **XChaCha20Poly1305** cipher.
//!
//! - **Output**: The encrypted data is then returned.
//!
//! ### Example
//!
//!
//! ```
//! use ncrypt_me::{encrypt_data, decrypt_data, Credentials, Argon2, secure_types::{SecureString, SecureBytes}};
//!
//! let exposed_data: Vec<u8> = vec![1, 2, 3, 4];
//! let credentials = Credentials::new(
//!  SecureString::from("username"),
//!  SecureString::from("password"),
//!  SecureString::from("password"),
//! );
//!
//! // I don't recommend using such low values, this is just an example
//!
//! let m_cost = 24_000;
//! let t_cost = 3;
//! let p_cost = 4;
//!
//! let argon2 = Argon2::new(m_cost, t_cost, p_cost);
//! let secure_data = SecureBytes::from_vec(exposed_data.clone()).unwrap();
//! let encrypted_data = encrypt_data(argon2, secure_data, credentials.clone()).unwrap();
//!
//! let decrypted_data = decrypt_data(encrypted_data, credentials).unwrap();
//!
//! decrypted_data.unlock_slice(|decrypted_slice| {
//!  assert_eq!(&exposed_data, decrypted_slice);
//! });
//! ```

pub mod credentials;
pub mod decrypt;
pub mod encrypt;
pub mod error;

pub use secure_types;

pub use credentials::Credentials;
pub use decrypt::decrypt_data;
pub use encrypt::{HEADER, HEADER_02, encrypt_data};

use error::Error;

pub use argon2_rs::Argon2;

const HEADER_LEN: usize = 8;
const ENCRYPTED_INFO_START: usize = 12;
pub const RECOMMENDED_SALT_LEN: usize = 64;

pub(crate) fn extract_encrypted_info_and_data(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
   if data.len() < HEADER_LEN {
      return Err(Error::InvalidFileFormat);
   }

   if &data[0..8] != HEADER_02 {
      return Err(Error::InvalidFileFormat);
   }

   if &data[0..8] == HEADER {
      return Err(Error::VersionMismatch);
   }

   if data.len() < ENCRYPTED_INFO_START {
      return Err(Error::EncryptedInfo);
   }

   let encrypted_info_length = u32::from_le_bytes(
      data[HEADER_LEN..ENCRYPTED_INFO_START]
         .try_into()
         .map_err(|_| Error::EncryptedInfo)?,
   );

   // The length comes from the file, so it can point far past the end of the buffer.
   // `checked_add` because on a 32 bit target the addition itself can overflow.
   let encrypted_info_end = ENCRYPTED_INFO_START
      .checked_add(encrypted_info_length as usize)
      .ok_or(Error::EncryptedInfo)?;
   if encrypted_info_end > data.len() {
      return Err(Error::EncryptedInfo);
   }

   let encrypted_info = &data[ENCRYPTED_INFO_START..encrypted_info_end];
   let encrypted_data = &data[encrypted_info_end..];
   Ok((encrypted_info.to_vec(), encrypted_data.to_vec()))
}

#[derive(Default, Clone, Debug)]
pub struct EncryptedInfo {
   pub password_salt: Vec<u8>,
   pub username_salt: Vec<u8>,
   pub cipher_nonce: Vec<u8>,
   pub argon2: Argon2,
}

impl EncryptedInfo {
   pub fn new(
      password_salt: Vec<u8>,
      username_salt: Vec<u8>,
      cipher_nonce: Vec<u8>,
      argon2: Argon2,
   ) -> Self {
      Self {
         password_salt,
         username_salt,
         cipher_nonce,
         argon2,
      }
   }

   pub fn encode(&self) -> Vec<u8> {
      let mut data = Vec::new();
      data.extend_from_slice(&self.password_salt);
      data.extend_from_slice(&self.username_salt);
      data.extend_from_slice(&self.cipher_nonce);
      data.extend_from_slice(&self.argon2.encode());
      data
   }

   pub fn from_encrypted_data(data: &[u8]) -> Result<Self, Error> {
      let (encrypted_info, _) = extract_encrypted_info_and_data(data)?;

      let salt_len = RECOMMENDED_SALT_LEN;
      if encrypted_info.len() < salt_len {
         return Err(Error::EncryptedInfo);
      }
      let password_salt = encrypted_info[0..salt_len].to_vec();

      if encrypted_info.len() < salt_len * 2 {
         return Err(Error::EncryptedInfo);
      }
      let username_salt = encrypted_info[salt_len..(salt_len * 2)].to_vec();

      let cipher_nonce_start = salt_len * 2;
      let cipher_nonce_end = cipher_nonce_start + 24;
      if encrypted_info.len() < cipher_nonce_end {
         return Err(Error::EncryptedInfo);
      }
      let cipher_nonce = encrypted_info[cipher_nonce_start..cipher_nonce_end].to_vec();

      // `Argon2::decode` handles a short remainder itself, it returns an error
      // instead of panicking, so the slice does not need a bound of its own.
      let argon2_start = cipher_nonce_end;
      let argon2 = Argon2::decode(&encrypted_info[argon2_start..])?;

      let info = EncryptedInfo {
         password_salt,
         username_salt,
         cipher_nonce,
         argon2,
      };

      Ok(info)
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use secure_types::{SecureBytes, SecureString};

   fn test_credentials() -> Credentials {
      Credentials::new(
         SecureString::from("username"),
         SecureString::from("password"),
         SecureString::from("password"),
      )
   }

   #[test]
   fn can_encrypt_decrypt() {
      let exposed_data: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      let credentials = Credentials::new(
         SecureString::from("username"),
         SecureString::from("password"),
         SecureString::from("password"),
      );

      let m_cost = 24_000;
      let t_cost = 3;
      let p_cost = 1;

      let argon2 = Argon2::new(m_cost, t_cost, p_cost);

      let secure_data = SecureBytes::from_vec(exposed_data.clone()).unwrap();

      let encrypted_data = encrypt_data(argon2, secure_data, credentials.clone()).unwrap();
      let decrypted_data = decrypt_data(encrypted_data, credentials).unwrap();

      decrypted_data.unlock_slice(|decrypted_data| {
         assert_eq!(exposed_data, decrypted_data);
      });
   }

   #[test]
   fn short_input_is_an_error() {
      // Too short to hold the 8 byte header.
      for len in [0, 1, 7, 8, 11] {
         let data = vec![0u8; len];

         assert!(matches!(
            decrypt_data(data.clone(), test_credentials()),
            Err(Error::InvalidFileFormat)
         ));
         assert!(matches!(
            decrypt::decrypt_data_unsecured(data, test_credentials()),
            Err(Error::InvalidFileFormat)
         ));
      }

      // A valid header, but truncated before the end of the length field.
      for len in HEADER_LEN..ENCRYPTED_INFO_START {
         let mut data = HEADER_02.to_vec();
         data.resize(len, 0);

         assert!(matches!(
            decrypt_data(data, test_credentials()),
            Err(Error::EncryptedInfo)
         ));
      }
   }

   #[test]
   fn declared_encrypted_info_length_past_the_end_is_an_error() {
      let mut data = HEADER_02.to_vec();
      data.extend_from_slice(&1024u32.to_le_bytes());
      data.extend_from_slice(&[0u8; 16]);

      assert!(matches!(
         decrypt_data(data, test_credentials()),
         Err(Error::EncryptedInfo)
      ));
   }

   #[test]
   fn encrypted_info_shorter_than_its_fields_is_an_error() {
      // 64 byte salts and a 24 byte nonce, each bound checked before its slice.
      for len in [0, 63, 64, 127, 128, 151] {
         let mut data = HEADER_02.to_vec();
         data.extend_from_slice(&(len as u32).to_le_bytes());
         data.resize(ENCRYPTED_INFO_START + len, 0);

         assert!(matches!(
            decrypt_data(data, test_credentials()),
            Err(Error::EncryptedInfo)
         ));
      }
   }

   #[test]
   fn argon2_parameters_shorter_than_decode_needs_is_an_error() {
      // `Argon2::decode` rejects anything under its 28 byte encoding.
      for len in [152, 179] {
         let mut data = HEADER_02.to_vec();
         data.extend_from_slice(&(len as u32).to_le_bytes());
         data.resize(ENCRYPTED_INFO_START + len, 0);

         assert!(matches!(
            decrypt_data(data, test_credentials()),
            Err(Error::Argon2(_))
         ));
      }
   }

   #[test]
   fn argon2_hash_length_below_the_cipher_key_size_is_an_error() {
      let mut encrypted_info = vec![0u8; RECOMMENDED_SALT_LEN * 2 + 24];
      let argon2 = Argon2::new(8, 1, 1).with_hash_length(4);
      encrypted_info.extend_from_slice(&argon2.encode());

      let mut data = HEADER_02.to_vec();
      data.extend_from_slice(&(encrypted_info.len() as u32).to_le_bytes());
      data.extend_from_slice(&encrypted_info);
      data.extend_from_slice(&[0u8; 16]);

      assert!(matches!(
         decrypt_data(data, test_credentials()),
         Err(Error::HashLength)
      ));
   }
}
