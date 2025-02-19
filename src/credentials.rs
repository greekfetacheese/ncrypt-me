use zeroize::Zeroize;
use super::error::CredentialsError;

/// The credentials needed to encrypt and decrypt a file.
///
/// Credentials are erased from memory when they are dropped.
/// 
/// But they can also be erased manually by calling the [Credentials::erase()] method
#[derive(Clone, Default)]
pub struct Credentials {
    username: String,
    password: String,
    confirm_password: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.erase();
    }
}

impl Credentials {
    pub fn new(username: String, password: String, confirm_password: String) -> Self {
        Self {
            username,
            password,
            confirm_password,
        }
    }

    /// Erases the credentials from memory by zeroizing the username and password fields.
    ///
    /// This method is automatically called when the `Credentials` instance is dropped.
    pub fn erase(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.confirm_password.zeroize();
    }

    pub fn username(&self) -> &String {
        &self.username
    }

    pub fn password(&self) -> &String {
        &self.password
    }

    pub fn confirm_password(&self) -> &String {
        &self.confirm_password
    }

    pub fn user_mut(&mut self) -> &mut String {
        &mut self.username
    }

    pub fn passwd_mut(&mut self) -> &mut String {
        &mut self.password
    }

    pub fn confirm_passwd_mut(&mut self) -> &mut String {
        &mut self.confirm_password
    }

    /// Copy password to confirm password
    pub fn copy_passwd_to_confirm(&mut self) {
        self.confirm_password.clear();
        self.confirm_password.push_str(&self.password);
    }

    pub fn is_valid(&self) -> Result<(), CredentialsError> {
        if self.username.is_empty() {
            return Err(CredentialsError::UsernameEmpty);
        }

        if self.password.is_empty() {
            return Err(CredentialsError::PasswordEmpty);
        }

        if self.confirm_password.is_empty() {
            return Err(CredentialsError::ConfirmPasswordEmpty);
        }

        if self.password != self.confirm_password {
            return Err(CredentialsError::PasswordsDoNotMatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials() {
        let mut credentials = Credentials::new("test".to_string(), "password".to_string(), "password".to_string());
        assert!(credentials.is_valid().is_ok());

        credentials.erase();
        assert_eq!(credentials.username().is_empty(), true);
        assert_eq!(credentials.password().is_empty(), true);
        assert_eq!(credentials.confirm_password().is_empty(), true);
    }
}
