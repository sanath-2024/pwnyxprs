package main

import "crypto/aes"

// helpers to encrypt & decrypt password data with AES256

func clamp(masterPassword string, length int) []byte {
	bytes := []byte(masterPassword)

	if len(bytes) > length {
		return bytes[:length]
	}

	zeroBytes := make([]byte, length-len(bytes))
	bytes = append(bytes, zeroBytes...)
	return bytes
}

// encrypt encrypts a password with AES256
func encrypt(password string, masterPassword string) ([]byte, PwnyXprsError) {
	// create a new cipher block from the master password
	cipherBlock, err_ := aes.NewCipher(clamp(masterPassword, 32))
	if err_ != nil {
		err := err_.Error()
		return nil, InternalError{&err}
	}

	// create a new byte array the size of the password + 1 for the length
	// of the password
	encryptedLen := len(password) + 8
	extraBytes := encryptedLen % 16
	// clamp to a multiple of 16
	if extraBytes != 0 {
		encryptedLen += (16 - extraBytes)
	}
	encrypted := make([]byte, encryptedLen)

	// set the first byte to the length of the password
	passwordLen := uint64(len(password))
	// big-endian
	encrypted[0] = byte(passwordLen >> 56)
	encrypted[1] = byte(passwordLen >> 48)
	encrypted[2] = byte(passwordLen >> 40)
	encrypted[3] = byte(passwordLen >> 32)
	encrypted[4] = byte(passwordLen >> 24)
	encrypted[5] = byte(passwordLen >> 16)
	encrypted[6] = byte(passwordLen >> 8)
	encrypted[7] = byte(passwordLen)

	// copy the password into the encrypted byte array
	copy(encrypted[8:], []byte(password))

	// encrypt the password
	for i := 0; i < len(encrypted); i += 16 {
		cipherBlock.Encrypt(encrypted[i:i+16], encrypted[i:i+16])
	}

	return encrypted, nil
}

// decrypt decrypts a password with AES256
func decrypt(encrypted []byte, masterPassword string) (string, PwnyXprsError) {
	// create a new cipher block from the master password
	cipherBlock, err_ := aes.NewCipher(clamp(masterPassword, 32))
	if err_ != nil {
		err := err_.Error()
		return "", InternalError{&err}
	}

	// decrypt the password
	for i := 0; i < len(encrypted); i += 16 {
		cipherBlock.Decrypt(encrypted[i:i+16], encrypted[i:i+16])
	}

	// get the length of the password
	passwordLen := int(uint64(encrypted[0])<<56 |
		uint64(encrypted[1])<<48 |
		uint64(encrypted[2])<<40 |
		uint64(encrypted[3])<<32 |
		uint64(encrypted[4])<<24 |
		uint64(encrypted[5])<<16 |
		uint64(encrypted[6])<<8 |
		uint64(encrypted[7]))

	if passwordLen < 0 {
		return "", AuthError{}
	}

	if passwordLen > len(encrypted)-8 {
		return "", AuthError{}
	}

	// return the decrypted password
	return string(encrypted[8 : passwordLen+8]), nil
}
