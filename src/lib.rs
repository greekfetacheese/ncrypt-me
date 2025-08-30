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
//! decrypted_data.slice_scope(|decrypted_slice| {
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
use error::{Error, map_argon2_error};
use secure_types::{SecureBytes, SecureString};
use zeroize::Zeroize;

use argon2_sys::{ARGON2_DEFAULT_FLAGS, argon2_context, argon2_ctx};

const HEADER_LEN: usize = 8;
const ENCRYPTED_INFO_START: usize = 12;
pub const RECOMMENDED_SALT_LEN: usize = 64;
pub const RECOMMENDED_HASH_LENGTH: u64 = 64;

/// Argon2 primitive type: variants of the algorithm.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Default, Ord, Encode, Decode)]
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
   #[default]
   Argon2id = 2,
}

/// Version of the algorithm.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Encode, Decode)]
#[repr(u32)]
pub enum Version {
   /// Version 16 (0x10 in hex)
   ///
   /// Performs overwrite internally
   V0x10 = 0x10,

   /// Version 19 (0x13 in hex, default)
   ///
   /// Performs XOR internally
   #[default]
   V0x13 = 0x13,
}

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

/// Argon2 instance
#[derive(Default, Clone, Debug, Encode, Decode)]
pub struct Argon2 {
   pub m_cost: u32,
   pub t_cost: u32,
   pub p_cost: u32,
   pub hash_length: u64,
   /// By default we use the Argon2id
   pub algorithm: Algorithm,
   /// By default we use the version 0x13
   pub version: Version,
}

impl Argon2 {
   pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
      Self {
         m_cost,
         t_cost,
         p_cost,
         hash_length: RECOMMENDED_HASH_LENGTH,
         ..Default::default()
      }
   }

   pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
      self.algorithm = algorithm;
      self
   }

   pub fn with_version(mut self, version: Version) -> Self {
      self.version = version;
      self
   }

   pub fn with_hash_length(mut self, hash_length: u64) -> Self {
      self.hash_length = hash_length;
      self
   }

   /// Hashes the given password
   ///
   /// ## Arguments
   ///
   /// - `password` - The password to hash
   /// - `salt` - The salt to use for hashing
   /// - `params` - The Argon2 parameters to use for hashing
   ///
   ///
   /// ## Returns
   ///
   /// The hash of the password in its raw byte form
   pub fn hash_password(
      &self,
      password: &SecureString,
      mut salt: Vec<u8>,
   ) -> Result<SecureBytes, Error> {
      let mut hash_buffer = vec![0u8; self.hash_length as usize];

      let code = password.str_scope(|password_str| {
         let mut context = argon2_context {
            out: hash_buffer.as_mut_ptr(),
            outlen: self.hash_length as u32,
            pwd: password_str.as_bytes().as_ptr() as *mut u8,
            pwdlen: password_str.len() as u32,
            salt: salt.as_mut_ptr(),
            saltlen: salt.len() as u32,
            secret: std::ptr::null_mut(),
            secretlen: 0,
            ad: std::ptr::null_mut(),
            adlen: 0,
            t_cost: self.t_cost,
            m_cost: self.m_cost,
            lanes: self.p_cost,
            threads: self.p_cost,
            version: self.version as u32,
            allocate_cbk: None,
            free_cbk: None,
            flags: ARGON2_DEFAULT_FLAGS,
         };

         unsafe { argon2_ctx(&mut context, self.algorithm as u32) }
      });

      salt.zeroize();

      if code != 0 {
         return Err(Error::Argon2(map_argon2_error(code)));
      }

      let secured_buffer =
         SecureBytes::from_vec(hash_buffer).map_err(|e| Error::Custom(e.to_string()))?;
      Ok(secured_buffer)
   }
}

// Argon2 Presets
impl Argon2 {
   pub fn very_fast() -> Self {
      Self {
         m_cost: 128_000,
         t_cost: 8,
         p_cost: 1,
         hash_length: RECOMMENDED_HASH_LENGTH,
         ..Default::default()
      }
   }

   pub fn fast() -> Self {
      Self {
         m_cost: 256_000,
         t_cost: 16,
         p_cost: 1,
         hash_length: RECOMMENDED_HASH_LENGTH,
         ..Default::default()
      }
   }

   pub fn balanced() -> Self {
      Self {
         m_cost: 1024_000,
         t_cost: 8,
         p_cost: 1,
         hash_length: RECOMMENDED_HASH_LENGTH,
         ..Default::default()
      }
   }

   pub fn slow() -> Self {
      Self {
         m_cost: 2048_000,
         t_cost: 8,
         p_cost: 1,
         hash_length: RECOMMENDED_HASH_LENGTH,
         ..Default::default()
      }
   }

   pub fn very_slow() -> Self {
      Self {
         m_cost: 3072_000,
         t_cost: 8,
         p_cost: 1,
         hash_length: RECOMMENDED_HASH_LENGTH,
         ..Default::default()
      }
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

      decrypted_data.slice_scope(|decrypted_data| {
         assert_eq!(exposed_data, decrypted_data);
      });
   }

   #[test]
   fn test_hash_password() {
      let password = SecureString::from("password");
      let salt = String::from("examplesaltvault").as_bytes().to_vec();

      let argon2 = Argon2::new(24_000, 3, 1);
      let _hash = argon2.hash_password(&password, salt).unwrap();

      password.str_scope(|password_str| {
         eprintln!("password_str: {}", password_str);
      });
   }
}
