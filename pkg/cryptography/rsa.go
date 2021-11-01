package cryptography

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	rsaKeyBitSize = 4096
)

var NoPemBlock = errors.New("[]byte does not contain public pem block")

// createRSAKey creates RSA keys with bitSize.
func createRSAKey(bitSize int) (privKey *rsa.PrivateKey, err error) {
	reader := rand.Reader
	if privKey, err = rsa.GenerateKey(reader, bitSize); err != nil {
		log.Debug(err)
		log.Error("Error while creating RSA key")
		return nil, err
	}
	return privKey, nil
}

// OpenPubKey opens public key named keyFileN in keyPath
func OpenPubKey(keyPath string, keyFileN string) (pubKey *rsa.PublicKey, err error) {
	pubFileN := filepath.Join(keyPath, keyFileN)
	if _, err := os.Stat(pubFileN); !os.IsNotExist(err) {
		// Read existing pubKey file
		pubFileBytes, err := ioutil.ReadFile(pubFileN)
		if err != nil {
			log.Debug(err)
			log.Error("Error while opening RSA pubKey in OpenKeysAsBlock")
			return nil, err
		}
		// Decode file and create block
		pubBlock, _ := pem.Decode(pubFileBytes)
		if pubBlock == nil {
			log.Error("Error while decoding pubKey file")
			return nil, err
		}

		if pubKey, err = x509.ParsePKCS1PublicKey(pubBlock.Bytes); err != nil {
			log.Debug(err)
			log.Error("Error while converting PEM block to keys")
			return nil, err
		}
		return pubKey, err
	} else {
		log.Debug(err)
		log.Error("pub key does not exist: " + keyFileN)
	}
	return nil, err
}

// OpenKeysAsBlock open existing keys and return them as *pem.Block.
// If keys are not found, new keys will be created.
func OpenKeysAsBlock(keyPath string) (pubBlock *pem.Block, privBlock *pem.Block, err error) {
	pubFileN := filepath.Join(keyPath, "key.pub")
	privFileN := filepath.Join(keyPath, "key.priv")

	// Check if keys already exist
	if _, err := os.Stat(pubFileN); !os.IsNotExist(err) {

		// Read existing pubKey file
		pubFileBytes, err := ioutil.ReadFile(pubFileN)
		if err != nil {
			log.Debug(err)
			log.Error("Error while opening RSA pubKey in OpenKeysAsBlock")
			return nil, nil, err
		}
		// Decode file and create block
		pubBlock, _ = pem.Decode(pubFileBytes)
		if pubBlock == nil {
			log.Error("Error while decoding pubKey file")
			return nil, nil, err
		}

		// Read existing privKey file
		privFileBytes, err := ioutil.ReadFile(privFileN)
		if err != nil {
			log.Debug(err)
			log.Error("Error while opening RSA private key file in OpenKeysAsBlock")
			return nil, nil, err
		}
		// Decode file and create block
		privBlock, _ = pem.Decode(privFileBytes)
		if privBlock == nil {
			log.Error("Error while decoding priv file")
			return nil, nil, err
		}
	} else if os.IsNotExist(err) {
		// Create directory if it doesn't exist
		if err := os.MkdirAll(keyPath, os.ModePerm); err != nil {
			log.Debug(err)
			log.Error("Error while creating key directory")
			return nil, nil, err
		}
		// Create new RSA key pair
		key, err := createRSAKey(rsaKeyBitSize)
		if err != nil {
			log.Debug(err)
			log.Error("Error while creating RSA key in OpenKeysAsBlock")
			return nil, nil, err
		}
		// Open pubKey file
		pubOut, err := os.Create(pubFileN)
		if err != nil {
			log.Debug(err)
			log.Error("Error while creating pubKey file")
			return nil, nil, err
		}
		// Close pubKey file when done
		defer func() {
			if errDef := pubOut.Close(); errDef != nil {
				log.Error(err)
				log.Error("Error while closing pubKey file")
				err = errDef
				return
			}
			if errDef := os.Chmod(pubFileN, 0644); errDef != nil {
				log.Debug(errDef)
				log.Error("Error while updating pubKey file permissions")
				err = errDef
				return
			}
		}()
		// Create PEM block
		pubBlock = &pem.Block{
			Type:    "RSA PUBLIC KEY",
			Headers: nil,
			Bytes:   x509.MarshalPKCS1PublicKey(&key.PublicKey),
		}
		// Write PEM block to pubKey file
		if err := pem.Encode(pubOut, pubBlock); err != nil {
			log.Debug(err)
			log.Error("Error while writing to pubKey file")
			return nil, nil, err
		}

		// Create privKey file
		privOut, err := os.OpenFile(privFileN, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
		if err != nil {
			log.Debug(err)
			log.Error("Error while creating private key in OpenKeysAsBlock")
			return nil, nil, err
		}
		// Close privKey file when done
		defer func() {
			if errDef := privOut.Close(); errDef != nil {
				log.Debug(errDef)
				log.Error("Error while closing private key file")
				err = errDef
				return
			}
			if errDef := os.Chmod(privFileN, 0600); errDef != nil {
				log.Debug(errDef)
				log.Error("Error while updating permissions")
				err = errDef
				return
			}
		}()
		// Create PEM block
		privBlock = &pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: nil,
			Bytes:   x509.MarshalPKCS1PrivateKey(key),
		}
		// Write PEM block to privKey file
		if err := pem.Encode(privOut, privBlock); err != nil {
			log.Debug(err)
			log.Error("Error while encoding private key")
			return nil, nil, err
		}
	} else {
		log.Debug(err)
		log.Error("Error while checking stat of the file")
	}
	return pubBlock, privBlock, err
}

// PemToKeys convert private PEM block to rsa.PrivateKey struct.
// *rsa.PrivateKey contains public key as well, so access public key
// with key.PublicKey
func PemToKeys(privBlock *pem.Block) (privKey *rsa.PrivateKey, err error) {
	if privKey, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes); err != nil {
		log.Debug(err)
		log.Error("Error while converting PEM block to keys")
		return nil, err
	}
	return privKey, nil
}

// PemToSha256 generates bytes containing sha256sum of pubBlock bytes.
func PemToSha256(pubBlock *pem.Block) []byte {
	// sha256sum always returns 32 bytes
	hash := sha256.Sum256(pubBlock.Bytes)
	return hash[:]
}

// BytesToPemFile writes pemBytes to fileName in PEM block format.
func BytesToPemFile(pemBytes []byte, fileName string) (err error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return NoPemBlock
	}
	if err = os.WriteFile(fileName, block.Bytes, 0x600); err != nil {
		return err
	}
	return nil
}

// EncryptSignMsg encrypts key for symmetric encryption with receiver's public key,
// and sign hashed symmetric encryption key with sender's private key.
func EncryptSignMsg(msg []byte, receiverPubKey *rsa.PublicKey, senderPrivKey *rsa.PrivateKey) (
	encryptedData []byte, dataSignature []byte, err error) {
	rng := rand.Reader
	// Encrypt symmetric encryption key
	if encryptedData, err = rsa.EncryptOAEP(sha256.New(), rng, receiverPubKey, msg, nil); err != nil {
		log.Debug(err)
		log.Error("Error while encrypting symmetric encryption key")
		return nil, nil, err
	}

	// Sign symmetric encryption key
	hashedKey := sha256.Sum256(msg)
	if dataSignature, err = rsa.SignPSS(rng, senderPrivKey, crypto.SHA256, hashedKey[:], nil); err != nil {
		log.Debug(err)
		log.Error("Error while signing symmetric encryption key")
		return nil, nil, err
	}

	return encryptedData, dataSignature, nil
}

// DecryptVerifyMsg decrypts key for symmetric encryption with receiver's private key,
// and verify signature with sender's public key.
func DecryptVerifyMsg(encryptedMsg []byte, signature []byte, senderPubKey *rsa.PublicKey, receiverPrivKey *rsa.PrivateKey) (
	symKey []byte, err error) {
	rng := rand.Reader

	// Decrypt symmetric encryption key
	if symKey, err = rsa.DecryptOAEP(sha256.New(), rng, receiverPrivKey, encryptedMsg, nil); err != nil {
		log.Debug(err)
		log.Error("Error while decrypting symmetric encryption key")
		return nil, err
	}

	// Verify symmetric encryption key signature
	hashedKey := sha256.Sum256(symKey)
	if err := rsa.VerifyPSS(senderPubKey, crypto.SHA256, hashedKey[:], signature, nil); err != nil {
		log.Debug(err)
		log.Error("Invalid symmetric encryption key signature")
		return nil, err
	}

	return symKey, nil
}
