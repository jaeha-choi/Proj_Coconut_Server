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
	"strings"
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
	block, err := OpenKeysAsBlock(keyPath, keyFileN)
	if err != nil {
		return nil, err
	}
	if pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
		log.Debug(err)
		log.Error("Error while converting PEM block to keys")
		return nil, err
	}
	return pubKey, err
}

// OpenPrivKey opens private key named keyFileN in keyPath
func OpenPrivKey(keyPath string, keyFileN string) (privKey *rsa.PrivateKey, err error) {
	block, err := OpenKeysAsBlock(keyPath, keyFileN)
	if err != nil {
		return nil, err
	}
	if privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		log.Debug(err)
		log.Error("Error while converting PEM block to keys")
		return nil, err
	}
	return privKey, err
}

// OpenKeysAsBlock open keys and return them as *pem.Block.
//
// If keyName ends with .priv
// - return private key block if found
// - return newly created private key pem block if not found
// If keyName ends anything else
// - return public key block if found
// - return err if not found
func OpenKeysAsBlock(keyPath string, keyName string) (keyBlock *pem.Block, err error) {
	keyF := filepath.Join(keyPath, keyName)
	if _, err = os.Stat(keyF); os.IsNotExist(err) && strings.HasSuffix(keyName, ".priv") {
		if err := os.MkdirAll(keyPath, os.ModePerm); err != nil {
			log.Debug(err)
			log.Error("Error while creating key directory")
			return nil, err
		}

		// Create new RSA key pair
		key, err := createRSAKey(rsaKeyBitSize)
		if err != nil {
			log.Debug(err)
			log.Error("Error while creating RSA key in OpenKeysAsBlock")
			return nil, err
		}

		name := keyF[:len(keyF)-5]
		// Create pubKey file
		pubOut, err := os.Create(name + ".pub")
		if err != nil {
			log.Debug(err)
			log.Error("Error while creating pubKey file")
			return nil, err
		}
		// Close pubKey file when done
		defer func() {
			if errDef := pubOut.Close(); errDef != nil {
				log.Error(err)
				log.Error("Error while closing pubKey file")
				err = errDef
				return
			}
			if errDef := os.Chmod(name+".pub", 0644); errDef != nil {
				log.Debug(errDef)
				log.Error("Error while updating pubKey file permissions")
				err = errDef
				return
			}
		}()
		// Create PEM block
		block := &pem.Block{
			Type:    "RSA PUBLIC KEY",
			Headers: nil,
			Bytes:   x509.MarshalPKCS1PublicKey(&key.PublicKey),
		}
		// Write PEM block to pubKey file
		if err := pem.Encode(pubOut, block); err != nil {
			log.Debug(err)
			log.Error("Error while writing to pubKey file")
			return nil, err
		}

		// Create privKey file
		privOut, err := os.OpenFile(name+".priv", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
		if err != nil {
			log.Debug(err)
			log.Error("Error while creating private key in OpenKeysAsBlock")
			return nil, err
		}
		// Close privKey file when done
		defer func() {
			if errDef := privOut.Close(); errDef != nil {
				log.Debug(errDef)
				log.Error("Error while closing private key file")
				err = errDef
				return
			}
			if errDef := os.Chmod(name+".priv", 0600); errDef != nil {
				log.Debug(errDef)
				log.Error("Error while updating permissions")
				err = errDef
				return
			}
		}()
		// Create PEM block
		keyBlock = &pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: nil,
			Bytes:   x509.MarshalPKCS1PrivateKey(key),
		}
		// Write PEM block to privKey file
		if err := pem.Encode(privOut, keyBlock); err != nil {
			log.Debug(err)
			log.Error("Error while encoding private key")
			return nil, err
		}

		// Return newly generated private key block
		return keyBlock, err
	} else if err != nil {
		return nil, err
	}
	fileBytes, err := ioutil.ReadFile(keyF)
	if err != nil {
		log.Debug(err)
		log.Error("Error while opening RSA pubKey in OpenKeysAsBlock")
		return nil, err
	}
	keyBlock, _ = pem.Decode(fileBytes)
	return keyBlock, err
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
