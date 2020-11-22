package des

import (
	"CryptoHashCodeClass3/utils"
	"crypto/cipher"
	"crypto/des"
)

//使用秘钥key对明文data进行加密
func DESEnCrypt(data []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//对尾部进行尾部填充
	originText := utils.PKCS5EndPadding(data, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	cipherText := make([]byte, len(originText))
	blockMode.CryptBlocks(cipherText, originText)
	return cipherText, nil
}

//使用des算法和秘钥key对密文进行解密,并去除尾部填充

func DesDeCrypt(data []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, key)
	originalText := make([]byte, len(data))
	mode.CryptBlocks(originalText, data)

	originalText = utils.ClearPKCS5Padding(originalText, block.BlockSize())
	return originalText, nil
}
