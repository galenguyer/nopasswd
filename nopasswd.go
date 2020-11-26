package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PasswordConfig is used to configure Argon2
type PasswordConfig struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	config := &PasswordConfig{
		time:    1,
		memory:  64 * 1024,
		threads: 4,
		keyLen:  32,
	}

	fmt.Print("-> Enter Password: ")
	pwinput, _ := reader.ReadString('\n')

	argon, argonHash, err := GeneratePassword(config, pwinput)
	if err != nil {
		panic(err)
	}

	_, err = os.Stat("./vault.data")
	if os.IsNotExist(err) {
		// Encryption
		text := "Mandalorian is currently the best DisneyPlus show"
		encrypted, _ := AESEncrypt(argonHash, text)
		err = ioutil.WriteFile("vault.data", []byte(argon+"\n"+encrypted), 0777)
		if err != nil {
			fmt.Println(err)
		}
	}

	// Decryption
	rawBytes, err := ioutil.ReadFile("vault.data")
	if err != nil {
		fmt.Println(err)
	}
	data := strings.Split(string(rawBytes), "\n")
	argonData := data[0]
	rawData := []byte(data[1])
	nHash, _ := GenerateHash(pwinput, argonData)
	decrypted, err := AESDecrypt(nHash, rawData)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
}

// AESEncrypt is used to encrypt a string with a given key
func AESEncrypt(key []byte, data string) (string, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(data), nil)), nil
}

// AESDecrypt is used to decrypt AES-encrypted bytes with a given key
func AESDecrypt(key []byte, data []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(string(data[:]))
	if err != nil {
		panic(err)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcmDecrypt, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}
	nonceSize := gcmDecrypt.NonceSize()
	if len(ciphertext) < nonceSize {
		panic(err)
	}
	nonce, encryptedMessage := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcmDecrypt.Open(nil, nonce, encryptedMessage, nil)
	if err != nil {
		panic(err)
	}
	return string(plaintext), nil
}

// GeneratePassword is used to generate a new password hash for storing and
// comparing at a later date.
func GeneratePassword(c *PasswordConfig, password string) (string, []byte, error) {
	// Generate a Salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", []byte(""), err
	}

	hash := argon2.IDKey([]byte(password), salt, c.time, c.memory, c.threads, c.keyLen)

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)

	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%d"
	most := fmt.Sprintf(format, argon2.Version, c.memory, c.time, c.threads, b64Salt, len(hash))
	return most, hash, nil
}

func GenerateHash(password string, config string) ([]byte, error) {
	parts := strings.Split(config, "$")
	c := &PasswordConfig{}
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &c.memory, &c.time, &c.threads)
	if err != nil {
		return []byte(""), err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return []byte(""), err
	}
	keyLen, err := strconv.Atoi(parts[5])
	if err != nil {
		return []byte(""), err
	}
	hash := argon2.IDKey([]byte(password), salt, c.time, c.memory, c.threads, uint32(keyLen))
	return hash, nil
}

// ComparePassword is used to compare a user-inputted password to a hash to see
// if the password matches or not.
func ComparePassword(password, hash string) (bool, error) {
	parts := strings.Split(hash, "$")

	c := &PasswordConfig{}
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &c.memory, &c.time, &c.threads)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	c.keyLen = uint32(len(decodedHash))

	comparisonHash := argon2.IDKey([]byte(password), salt, c.time, c.memory, c.threads, c.keyLen)

	return (subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1), nil
}
