# Utility for Project Coconut Server/Desktop

[![CI](https://github.com/jaeha-choi/Proj_Coconut_Utility/actions/workflows/CI.yml/badge.svg)](https://github.com/jaeha-choi/Proj_Coconut_Utility/actions/workflows/CI.yml)
[![codecov](https://codecov.io/gh/jaeha-choi/Proj_Coconut_Utility/branch/master/graph/badge.svg?token=OO62TDTYH2)](https://codecov.io/gh/jaeha-choi/Proj_Coconut_Utility)

### `log` package

Contains simple wrapper methods to support level-based logging.

#### Usage
```go
import "github.com/jaeha-choi/Proj_Coconut_Utility/log"

// Initialize logger
log.Init(os.Stdout, log.Error) 

log.Debug("Debug msg") // Won't print; Mode is set to log.Error
log.Error(err)
```

### `util` package

Contains utility methods for sending/receiving packets and defined status codes.

### `cryptography` package

Note: I am not a cryptographer. Use this package at your own risk. If you notice any security issue,
please [email me](mailto:jaeha@mail.jaeha.dev).

Provide functions to encrypt/decrypt large files in chunks using AES-GCM and RSA.

#### Usage

- Encryption (AES-GCM + RSA):

```go
... 
streamEncrypt, err := cryptography.EncryptSetup(testFileN)
// Error handling
err = streamEncrypt.Encrypt(writer, client1PublicKey, client2PrivKey)
// Error handling
err := streamEncrypt.Close()
...
```

- Decryption (AES-GCM + RSA):

```go
...
streamDecrypt, err := cryptography.DecryptSetup()
// Error handling
err = streamDecrypt.Decrypt(reader, client2PublicKey, client1PrivKey)
// Error handling
err := streamDecrypt.Close()
...
```

- Encryption (RSA):

```go
cryptography.EncryptSignMsg(msg, client1PublicKey, client2PrivKey)
```

- Decryption (RSA):

```go
cryptography.DecryptVerifyMsg(encryptedMsg, client2PublicKey, client1PrivKey)
```

- Open RSA PEM blocks:

```go
pubPem, privPem, err := OpenKeys("./path/to/keys/")
```

- PEM blocks to PrivateKey struct:

```go
privKey, err := PemToKeys(privPem)

privKey             // Private key
privKey.PublicKey   // Public key
```