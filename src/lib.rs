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
pub use zeroize;

pub use credentials::Credentials;
pub use decrypt::decrypt_data;
pub use encrypt::encrypt_data;

use bincode::{Decode, Encode, config::standard, decode_from_slice};
use error::Error;
use zeroize::Zeroize;

pub use argon2_rs::Argon2;

const HEADER_LEN: usize = 8;
const ENCRYPTED_INFO_START: usize = 12;
pub const RECOMMENDED_SALT_LEN: usize = 64;

pub(crate) fn extract_encrypted_info_and_data(
   encrypted_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
   let encrypted_info_length = u32::from_le_bytes(
      encrypted_data[HEADER_LEN..ENCRYPTED_INFO_START]
         .try_into()
         .map_err(|_| Error::EncryptedInfo)?,
   );

   let encrypted_info_end = ENCRYPTED_INFO_START + (encrypted_info_length as usize);
   let encrypted_info = &encrypted_data[ENCRYPTED_INFO_START..encrypted_info_end];
   let encrypted_data = &encrypted_data[encrypted_info_end..];
   Ok((encrypted_info.to_vec(), encrypted_data.to_vec()))
}

#[derive(Default, Clone, Debug, Encode, Decode)]
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

   pub fn from_encrypted_data(data: &[u8]) -> Result<Self, Error> {
      let (encrypted_info, _) = extract_encrypted_info_and_data(data)?;

      let info: (EncryptedInfo, usize) = decode_from_slice(&encrypted_info, standard())
         .map_err(|e| Error::DecodingFailed(e.to_string()))?;

      Ok(info.0)
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use secure_types::{SecureBytes, SecureString};

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
}
