use super::error::CredentialsError;
use secure_types::SecureString;

/// The credentials needed to encrypt and decrypt a file.
///
/// Credentials are erased from memory when they are dropped.
///
/// But they can also be erased manually by calling the [Credentials::erase()]
#[derive(Clone)]
pub struct Credentials {
   pub username: SecureString,
   pub password: SecureString,
   pub confirm_password: SecureString,
}

impl Credentials {
    pub fn new(
        username: SecureString,
        password: SecureString,
        confirm_password: SecureString,
    ) -> Self {
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
        self.username.erase();
        self.password.erase();
        self.confirm_password.erase();
    }

    pub fn username(&self) -> &str {
        self.username.borrow()
    }

    pub fn password(&self) -> &str {
        self.password.borrow()
    }

    pub fn confirm_password(&self) -> &str {
        self.confirm_password.borrow()
    }

    /// Copy password to confirm password
    pub fn copy_passwd_to_confirm(&mut self) {
        let passwd = self.password.borrow();
        self.confirm_password.erase();
        self.confirm_password.string_mut(|s| s.push_str(passwd));
    }

    pub fn is_valid(&self) -> Result<(), CredentialsError> {
        if self.username().is_empty() {
            return Err(CredentialsError::UsernameEmpty);
        }

        if self.password().is_empty() {
            return Err(CredentialsError::PasswordEmpty);
        }

        if self.confirm_password().is_empty() {
            return Err(CredentialsError::ConfirmPasswordEmpty);
        }

        if self.password() != self.confirm_password() {
            return Err(CredentialsError::PasswordsDoNotMatch);
        }
        Ok(())
    }
}

impl Default for Credentials {
    fn default() -> Self {
        Self::new(
            SecureString::from(""),
            SecureString::from(""),
            SecureString::from(""),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials() {
        let mut credentials = Credentials::new(
            SecureString::from("username"),
            SecureString::from("password"),
            SecureString::from("password"),
        );
        assert!(credentials.is_valid().is_ok());

        credentials.erase();
        assert_eq!(credentials.username().is_empty(), true);
        assert_eq!(credentials.password().is_empty(), true);
        assert_eq!(credentials.confirm_password().is_empty(), true);
    }

    #[test]
    fn test_copy_passwd_to_confirm() {
        let mut credentials = Credentials::new(
            SecureString::from("username"),
            SecureString::from("password"),
            SecureString::from("something_else"),
        );

        credentials.copy_passwd_to_confirm();
        assert!(credentials.is_valid().is_ok());
    }

    #[test]
    fn test_default() {
        let credintials = Credentials::default();
        assert_eq!(credintials.username().is_empty(), true);
        assert_eq!(credintials.password().is_empty(), true);
        assert_eq!(credintials.confirm_password().is_empty(), true);
    }
}
