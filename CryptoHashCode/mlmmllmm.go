package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
)

func main() {
	key := []byte("00000000")
	arr := "斑马斑马"
	fmt.Println("--------DES加密解密字节数组")
	fmt.Println("加密前：", arr)
	resultArr, _ := DesEncrypt([]byte(arr), key)
	fmt.Println("加密后:", resultArr)
	resultArr,_ = DesDecrypt(resultArr,key)
	fmt.Println("解密后：",string(resultArr))
	fmt.Println("---------DES加密解密字符串")
	cipherText , _ := DesEncryptString(arr,key)
	fmt.Println("加密后：",cipherText)
	originalText ,_ :=DesDecryptString(cipherText,key)
	fmt.Println("解密后：",originalText)
}

//DES加密字节数组，返数回字节组
func DesEncrypt(orginalBytes, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	orginalBytes = PKCS5Padding(orginalBytes, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	cipherArr := make([]byte, len(orginalBytes))
	blockMode.CryptBlocks(cipherArr, orginalBytes)
	return cipherArr, nil
}

//DES解密字节数组，返回字节数组
func DesDecrypt(cipherBytes, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	originalText := make([]byte, len(cipherBytes))
	blockMode.CryptBlocks(originalText, cipherBytes)
	originalText = PKCS5UnPadding(originalText)
	return originalText, nil

}

//DES加密文本，返回加密后文本
func DesEncryptString(originalText string, key []byte) (string, error) {
	cipherArr, err := DesEncrypt([]byte(originalText), key)
	if err != nil {
		return "", err
	}
	base64str := base64.StdEncoding.EncodeToString(cipherArr)
	return base64str, nil
}

//对加密文本进行DES解密，返回解密后明文
func DesDecryptString(cipherText string, key []byte) (string, error) {
	cipherArr, _ := base64.StdEncoding.DecodeString(cipherText)
	cipherArr, err := DesDecrypt(cipherArr, key)
	if err != nil {
		return "", err
	}
	return string(cipherArr), nil
}

//尾部填充
func PKCS5Padding(cipherText []byte, blockSize int) []byte {
 padding := blockSize - len(cipherText)% blockSize
 padtext :=bytes.Repeat([]byte{byte(padding)},padding)
 return append(cipherText,padtext...)
}

func PKCS5UnPadding(orinData []byte) []byte {
   length := len(orinData)
   unpadding :=int(orinData[length-1])
   return orinData[:(length-unpadding)]
}
