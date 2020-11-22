package aes

import (
	"CryptoHashCode/utils"
	"crypto/aes"
	"crypto/cipher"
)

func AESEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	originData := utils.PkCS5EndPadding(data, block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	cipherText := make([]byte, len(originData))
	mode.CryptBlocks(cipherText, originData)
	return cipherText, nil
}
func AESDecrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	originalText := make([]byte, len(data))
	mode.CryptBlocks(originalText, data)

	originalText = utils.ClearPACS5Padding(originalText)
	return originalText, nil
}
