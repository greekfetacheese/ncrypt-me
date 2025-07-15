use thiserror::Error as ThisError;

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

#[derive(ThisError, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Argon2Error {
    #[error("Output pointer is null")]
    OutputPtrNull,
    #[error("Output is too short")]
    OutputTooShort,
    #[error("Output is too long")]
    OutputTooLong,
    #[error("Password is too short")]
    PasswordTooShort,
    #[error("Password is too long")]
    PasswordTooLong,
    #[error("Salt is too short")]
    SaltTooShort,
    #[error("Salt is too long")]
    SaltTooLong,
    #[error("Associated data is too short")]
    AdTooShort,
    #[error("Associated data is too long")]
    AdTooLong,
    #[error("Secret is too short")]
    SecretTooShort,
    #[error("Secret is too long")]
    SecretTooLong,
    #[error("Time cost is too small")]
    TimeTooSmall,
    #[error("Time cost is too large")]
    TimeTooLarge,
    #[error("Memory cost is too little")]
    MemoryTooLittle,
    #[error("Memory cost is too much")]
    MemoryTooMuch,
    #[error("Number of lanes is too few")]
    LanesTooFew,
    #[error("Number of lanes is too many")]
    LanesTooMany,
    #[error("Password pointer mismatch")]
    PwdPtrMismatch,
    #[error("Salt pointer mismatch")]
    SaltPtrMismatch,
    #[error("Secret pointer mismatch")]
    SecretPtrMismatch,
    #[error("Associated data pointer mismatch")]
    AdPtrMismatch,
    #[error("Memory allocation error")]
    MemoryAllocationError,
    #[error("Free memory callback is null")]
    FreeMemoryCbkNull,
    #[error("Allocate memory callback is null")]
    AllocateMemoryCbkNull,
    #[error("Incorrect parameter")]
    IncorrectParameter,
    #[error("Incorrect Argon2 type")]
    IncorrectType,
    #[error("Output pointer mismatch")]
    OutPtrMismatch,
    #[error("Number of threads is too few")]
    ThreadsTooFew,
    #[error("Number of threads is too many")]
    ThreadsTooMany,
    #[error("Missing arguments")]
    MissingArgs,
    #[error("Encoding failed")]
    EncodingFail,
    #[error("Decoding failed")]
    DecodingFail,
    #[error("Thread failed")]
    ThreadFail,
    #[error("Decoding length failed")]
    DecodingLengthFail,
    #[error("Verification mismatch")]
    VerifyMismatch,
    #[error("Unknown argon2 error with code: {0}")]
    Unknown(i32)
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


pub(crate) fn map_argon2_error(code: i32) -> Argon2Error {
    match code {
        -1 => Argon2Error::OutputPtrNull,
        -2 => Argon2Error::OutputTooShort,
        -3 => Argon2Error::OutputTooLong,
        -4 => Argon2Error::PasswordTooShort,
        -5 => Argon2Error::PasswordTooLong,
        -6 => Argon2Error::SaltTooShort,
        -7 => Argon2Error::SaltTooLong,
        -8 => Argon2Error::AdTooShort,
        -9 => Argon2Error::AdTooLong,
        -10 => Argon2Error::SecretTooShort,
        -11 => Argon2Error::SecretTooLong,
        -12 => Argon2Error::TimeTooSmall,
        -13 => Argon2Error::TimeTooLarge,
        -14 => Argon2Error::MemoryTooLittle,
        -15 => Argon2Error::MemoryTooMuch,
        -16 => Argon2Error::LanesTooFew,
        -17 => Argon2Error::LanesTooMany,
        -18 => Argon2Error::PwdPtrMismatch,
        -19 => Argon2Error::SaltPtrMismatch,
        -20 => Argon2Error::SecretPtrMismatch,
        -21 => Argon2Error::AdPtrMismatch,
        -22 => Argon2Error::MemoryAllocationError,
        -23 => Argon2Error::FreeMemoryCbkNull,
        -24 => Argon2Error::AllocateMemoryCbkNull,
        -25 => Argon2Error::IncorrectParameter,
        -26 => Argon2Error::IncorrectType,
        -27 => Argon2Error::OutPtrMismatch,
        -28 => Argon2Error::ThreadsTooFew,
        -29 => Argon2Error::ThreadsTooMany,
        -30 => Argon2Error::MissingArgs,
        -31 => Argon2Error::EncodingFail,
        -32 => Argon2Error::DecodingFail,
        -33 => Argon2Error::ThreadFail,
        -34 => Argon2Error::DecodingLengthFail,
        -35 => Argon2Error::VerifyMismatch,
        _ => Argon2Error::Unknown(code),
    }
}