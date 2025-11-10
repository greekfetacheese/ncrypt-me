use thiserror::Error as ThisError;
use argon2_rs::error::Argon2Error;

#[derive(ThisError, Debug)]
pub enum Error {
   #[error("Hash Length cannot be less than 32 bytes")]
   HashLength,

   #[error("Header not found, data corrupted?")]
   InvalidFileFormat,

   #[error("Could not parse EncryptedInfo length")]
   EncryptedInfo,

   #[error("Invalid Credentials {0}")]
   InvalidCredentials(String),

   #[error("EncrytedInfo Encoding Failed {0}")]
   EncodingFailed(String),

   #[error("Encryption Failed {0}")]
   EncryptionFailed(String),

   #[error("EncryptedInfo Decoding Failed {0}")]
   DecodingFailed(String),

   #[error("Decryption Failed {0}")]
   DecryptionFailed(String),

   #[error("Failed to read file {0}")]
   FileReadFailed(String),

   #[error("Argon2 error: {0}")]
   Argon2(#[from] Argon2Error),

   #[error("{0}")]
   Credentials(#[from] CredentialsError),

   #[error("{0}")]
   Custom(String),
}


#[derive(ThisError, Debug)]
pub enum CredentialsError {
   #[error("Username is empty")]
   UsernameEmpty,

   #[error("Password is empty")]
   PasswordEmpty,

   #[error("Confirm password is empty")]
   ConfirmPasswordEmpty,

   #[error("Passwords do not match")]
   PasswordsDoNotMatch,

   #[error("{0}")]
   Custom(String),
}