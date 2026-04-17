use std::fmt::{Debug, Display, Formatter};

use argon2_rs::error::Argon2Error;

#[derive(Clone, PartialEq, Eq)]
pub enum Error {
   HashLength,
   InvalidFileFormat,
   VersionMismatch,
   EncryptedInfo,
   InvalidCredentials,
   EncodingFailed,
   EncryptionFailed(String),
   DecodingFailed,
   DecryptionFailed(String),
   FileReadFailed,
   Argon2(Argon2Error),
   Credentials(CredentialsError),
   Custom(String),
}

impl From<Argon2Error> for Error {
   fn from(e: Argon2Error) -> Self {
      Error::Argon2(e)
   }
}

impl From<CredentialsError> for Error {
   fn from(e: CredentialsError) -> Self {
      Error::Credentials(e)
   }
}

impl Display for Error {
   fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
      match self {
         Error::HashLength => write!(f, "Hash Length cannot be less than 32 bytes"),
         Error::InvalidFileFormat => write!(f, "Header not found, data corrupted?"),
         Error::VersionMismatch => write!(
            f,
            "Version mismatch. It seems this data was encrypted with a different version that it's not compatible with the current version"
         ),
         Error::EncryptedInfo => write!(f, "Could not parse EncryptedInfo length"),
         Error::InvalidCredentials => write!(f, "Invalid Credentials"),
         Error::EncodingFailed => write!(f, "EncrytedInfo Encoding Failed"),
         Error::EncryptionFailed(e) => write!(f, "Encryption Failed: {}", e),
         Error::DecodingFailed => write!(f, "EncryptedInfo Decoding Failed"),
         Error::DecryptionFailed(e) => write!(f, "Decryption Failed: {}", e),
         Error::FileReadFailed => write!(f, "Failed to read file"),
         Error::Argon2(e) => write!(f, "Argon2 error: {}", e),
         Error::Credentials(e) => write!(f, "Credentials error: {}", e),
         Error::Custom(e) => write!(f, "{}", e),
      }
   }
}

impl Debug for Error {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f, "{}", self)
   }
}

impl std::error::Error for Error {}

#[derive(Clone, PartialEq, Eq)]
pub enum CredentialsError {
   UsernameEmpty,
   PasswordEmpty,
   ConfirmPasswordEmpty,
   PasswordsDoNotMatch,
   Custom(String),
}

impl Display for CredentialsError {
   fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
      match self {
         CredentialsError::UsernameEmpty => write!(f, "Username is empty"),
         CredentialsError::PasswordEmpty => write!(f, "Password is empty"),
         CredentialsError::ConfirmPasswordEmpty => write!(f, "Confirm password is empty"),
         CredentialsError::PasswordsDoNotMatch => write!(f, "Passwords do not match"),
         CredentialsError::Custom(e) => write!(f, "{}", e),
      }
   }
}

impl Debug for CredentialsError {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f, "{}", self)
   }
}

impl std::error::Error for CredentialsError {}
