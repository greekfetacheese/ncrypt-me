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

   /// Creates a new `Credentials` instance with the specified capacity.
   pub fn new_with_capacity(capacity: usize) -> Result<Self, CredentialsError> {
      let username = SecureString::new_with_capacity(capacity)
         .map_err(|e| CredentialsError::Custom(e.to_string()))?;

      let password = SecureString::new_with_capacity(capacity)
         .map_err(|e| CredentialsError::Custom(e.to_string()))?;

      let confirm_password = SecureString::new_with_capacity(capacity)
         .map_err(|e| CredentialsError::Custom(e.to_string()))?;
      Ok(Self {
         username,
         password,
         confirm_password,
      })
   }

   /// Erases the credentials from memory by zeroizing the username and password fields.
   ///
   /// This method is automatically called when the `Credentials` instance is dropped.
   pub fn erase(&mut self) {
      self.username.erase();
      self.password.erase();
      self.confirm_password.erase();
   }

   /// Copy password to confirm password
   pub fn copy_passwd_to_confirm(&mut self) {
      self.password.unlock_str(|str| {
         self.confirm_password.erase();
         self.confirm_password.push_str(str);
      });
   }

   pub fn is_valid(&self) -> Result<(), CredentialsError> {
      if self.username.char_len() == 0 {
         return Err(CredentialsError::UsernameEmpty);
      }

      if self.password.char_len() == 0 {
         return Err(CredentialsError::PasswordEmpty);
      }

      if self.confirm_password.char_len() == 0 {
         return Err(CredentialsError::ConfirmPasswordEmpty);
      }

      let res = self.password.unlock_str(|password| {
         self.confirm_password.unlock_str(|confirm_password| {
            if password != confirm_password {
               return Err(CredentialsError::PasswordsDoNotMatch);
            } else {
               Ok(())
            }
         })
      });
      res
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
   fn test_copy_passwd_to_confirm() {
      let mut credentials = Credentials::new(
         SecureString::from("username"),
         SecureString::from("password"),
         SecureString::from("something_else"),
      );

      credentials.copy_passwd_to_confirm();
      assert!(credentials.is_valid().is_ok());
   }
}
