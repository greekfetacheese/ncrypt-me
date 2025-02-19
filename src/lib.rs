//! ## How the data is encrypted
//!
//! Given some Credentials (username and password) we hash the password and username using Argon2
//!
//! and use the resulting hash of the password as the key for the XChaCha20Poly1305 cipher
//!
//! and the resulting hash of the username as the Additional Authenticated Data (AAD) for the cipher
//! 
//! Finally we encrypt the data using the cipher
//!
//! ### Example:
//!
//! ```
//! use ncrypt_me::{encrypt_data, decrypt_data, Credentials, Argon2Params};
//!
//! let some_data = vec![1, 2, 3, 4]
//! let credentials = Credentials::new(
//! "username".to_string(),
//! "password".to_string(),
//! "password".to_string());
//!
//! let argon_params = Argon2Params::fast();
//! let encrypted_data = encrypt_data(argon_params, some_data.clone(), credentials.clone()).unwrap();
//!
//! let decrypted_data = decrypt_data(encrypted_data, credentials).unwrap();
//!
//! assert_eq!(some_data, decrypted_data);
//! ```
//!
//! ### Extracting the Encrypted Info
//!
//! The Encrypted Info contains the following information:
//! 1. Password Salt used for the password hashing
//! 2. Username Salt used for the username hashing
//! 3. Cipher Nonce used for the XChaCha20Poly1305 cipher
//! 4. Argon2 Parameters used for the username & password hashing
//!
//! ```
//! use ncrypt_me::EncryptedInfo;
//!
//! let path = "your_file.ncrypt";
//! let info = EncryptedInfo::from_file(&path).unwrap();
//!
//! // or you can use the EncryptedInfo::from_encrypted_data method
//!
//! println!("{:?}", info);
//! ```

pub mod credentials;
pub mod decrypt;
pub mod encrypt;
pub mod error;

pub use argon2::Argon2;
pub use zeroize;

pub use encrypt::encrypt_data;
pub use decrypt::decrypt_data;
pub use credentials::Credentials;

use error::Error;
use zeroize::Zeroize;
use argon2::password_hash::Output;


pub fn erase_output(output: &mut Output) {
    unsafe {
        let ptr: *mut Output = output;

        let size = std::mem::size_of::<Output>();
        let bytes: &mut [u8] = std::slice::from_raw_parts_mut(ptr as *mut u8, size);

        bytes.zeroize();
    }
}


fn extract_encrypted_info(encrypted_data: &[u8]) -> Result<Vec<u8>, Error> {
    let encrypted_info_length = u32::from_le_bytes(
        encrypted_data[8..12].try_into().map_err(|_| Error::EncryptedInfo)?
    );

    let encrypted_info_start = 12;
    let encrypted_info_end = encrypted_info_start + (encrypted_info_length as usize);
    Ok(encrypted_data[encrypted_info_start..encrypted_info_end].to_vec())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedInfo {
    pub password_salt: String,
    pub username_salt: String,
    pub cipher_nonce: Vec<u8>,
    pub argon2_params: Argon2Params,
}

impl EncryptedInfo {
    pub fn new(
        password_salt: String,
        username_salt: String,
        cipher_nonce: Vec<u8>,
        argon2_params: Argon2Params
    ) -> Self {
        Self {
            password_salt,
            username_salt,
            cipher_nonce,
            argon2_params,
        }
    }

    pub fn from_encrypted_data(data: &[u8]) -> Result<Self, Error> {
        let encrypted_info = extract_encrypted_info(data)?;

        let info: EncryptedInfo = bincode
            ::deserialize(&encrypted_info)
            .map_err(|e| Error::DeserializationFailed(e.to_string()))?;

        Ok(info)
    }

    pub fn from_file(dir: &std::path::PathBuf) -> Result<Self, Error> {
        let data = std::fs::read(dir).map_err(|e| Error::FileReadFailed(e.to_string()))?;
        let encrypted_info = extract_encrypted_info(&data)?;

        let info: EncryptedInfo = bincode
            ::deserialize(&encrypted_info)
            .map_err(|e| Error::DeserializationFailed(e.to_string()))?;

        Ok(Self {
            password_salt: info.password_salt,
            username_salt: info.username_salt,
            cipher_nonce: info.cipher_nonce,
            argon2_params: info.argon2_params,
        })
    }
}

/// Argon2 parameters
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub hash_length: u64,
}

impl Argon2Params {
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32, hash_length: u64) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
            hash_length,
        }
    }

    pub fn from_argon2(argon2: Argon2) -> Result<Self, Error> {
        let hash_lenght = argon2.params().output_len();

        if hash_lenght.is_none() {
            return Err(Error::Custom("Hash length is none".to_string()));
        }

        Ok(Self {
            m_cost: argon2.params().m_cost(),
            t_cost: argon2.params().t_cost(),
            p_cost: argon2.params().p_cost(),
            hash_length: hash_lenght.unwrap() as u64,
        })
    }
}

// Argon2Params Presets
impl Argon2Params {
    pub fn very_fast() -> Self {
        Self {
            m_cost: 64_000,
            t_cost: 3,
            p_cost: 1,
            hash_length: 64,
        }
    }

    pub fn fast() -> Self {
        Self {
            m_cost: 128_000,
            t_cost: 5,
            p_cost: 1,
            hash_length: 64,
        }
    }

    pub fn balanced() -> Self {
        Self {
            m_cost: 256_000,
            t_cost: 5,
            p_cost: 1,
            hash_length: 64,
        }
    }

    pub fn slow() -> Self {
        Self {
            m_cost: 512_000,
            t_cost: 5,
            p_cost: 1,
            hash_length: 64,
        }
    }

    pub fn very_slow() -> Self {
        Self {
            m_cost: 1024_000,
            t_cost: 5,
            p_cost: 1,
            hash_length: 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::encrypt::encrypt_data;
    use super::decrypt::decrypt_data;
    use super::credentials::Credentials;
    use super::Argon2Params;
    use argon2::password_hash::{Output, Encoding};

    #[test]
    fn erase_output_works() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut output = Output::new_with_encoding(&data, Encoding::Crypt).unwrap();
        super::erase_output(&mut output);
        
        let bytes = output.as_bytes();
        assert_eq!(bytes, &[0; 0]);
    }

    #[test]
    fn can_encrypt_decrypt() {
        let some_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let credentials = Credentials::new(
            "username".to_string(),
            "password".to_string(),
            "password".to_string()
        );

        let argon_params = Argon2Params {
            m_cost: 24_000,
            t_cost: 3,
            p_cost: 1,
            hash_length: 64,
        };

        let encrypted_data = encrypt_data(
            argon_params,
            some_data.clone(),
            credentials.clone()
        ).expect("Failed to encrypt data");

        std::fs
            ::write("test.ncrypt", &encrypted_data)
            .expect("Failed to write encrypted data to file");

        let encrypted_data = std::fs
            ::read("test.ncrypt")
            .expect("Failed to read encrypted data from file");

        let decrypted_data = decrypt_data(encrypted_data, credentials).expect(
            "Failed to decrypt data"
        );

        assert_eq!(some_data, decrypted_data);

        std::fs::remove_file("test.ncrypt").expect("Failed to remove test file");
    }
}
