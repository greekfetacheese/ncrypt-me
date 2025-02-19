use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {

    #[error("Hash Length cannot be less than 32 bytes")]
    HashLength,

    #[error("Header not found, invalid file format?")]
    InvalidFileFormat,

    #[error("Could not parse EncryptedInfo length")]
    EncryptedInfo,

    #[error("Invalid Credentials {0}")]
    InvalidCredentials(String),

    #[error("Invalid Argon2 parameters {0}")]
    InvalidArgon2Params(String),

    #[error("Could not parse password salt {0}")]
    PasswordSalt(String),

    #[error("Could not parse username salt {0}")]
    UsernameSalt(String),

    #[error("Password hashing failed {0}")]
    PasswordHashingFailed(String),

    #[error("Username hashing failed {0}")]
    UsernameHashingFailed(String),

    #[error("Password hash output not found")]
    PasswordHashOutput,

    #[error("Username hash output not found")]
    UsernameHashOutput,

    #[error("EncrytedInfo Serialization Failed {0}")]
    SerializationFailed(String),

    #[error("Encryption Failed {0}")]
    EncryptionFailed(String),

    #[error("Deserialization Failed {0}")]
    DeserializationFailed(String),

    #[error("Decryption Failed {0}")]
    DecryptionFailed(String),

    #[error("Failed to read file {0}")]
    FileReadFailed(String),

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
}