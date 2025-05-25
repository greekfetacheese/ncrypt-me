# ncrypt_me - Secure Data Encryption


## How the Data is Encrypted

Given some `Credentials` (username and password), the process for encrypting data involves:

- **Hashing**: Both the password and username are hashed using **Argon2**.
  - The resulting hash of the **password** is used as the **key** for the **XChaCha20Poly1305** cipher.
  - The resulting hash of the **username** serves as the **Additional Authenticated Data (AAD)** for the cipher.

- **Encryption**: With the key and AAD set, the data is encrypted using the **XChaCha20Poly1305** cipher.

- **Output**: The encrypted data is then returned.

### Example


```rust
use ncrypt_me::{encrypt_data, decrypt_data, Credentials, Argon2Params};

let some_data = vec![1, 2, 3, 4];
let credentials = Credentials::new(
 SecureString::from("username"),
 SecureString::from("password"),
 SecureString::from("password"),
 );

let argon_params = Argon2Params::fast();
let encrypted_data = encrypt_data(argon_params, some_data.clone(), credentials.clone()).unwrap();

let decrypted_data = decrypt_data(encrypted_data, credentials).unwrap();

assert_eq!(some_data, decrypted_data);
```

### The safer way to create a new `Credentials` instance that is going to be mutated

```rust
// Make sure to give enough capacity so the inner `Vec` doesn't reallocate
let credentials = Credentials::new_with_capacity(1024);
```



### Extracting the Encrypted Info

The Encrypted Info contains the following information:
- Password Salt used for the password hashing
- Username Salt used for the username hashing
- Cipher Nonce used for the XChaCha20Poly1305 cipher
- Argon2 Parameters used for the username & password hashing

```rust
use ncrypt_me::EncryptedInfo;

let path = "your_file.ncrypt";
let info = EncryptedInfo::from_file(&path).unwrap();

// or you can use the EncryptedInfo::from_encrypted_data method

println!("{:?}", info);
```