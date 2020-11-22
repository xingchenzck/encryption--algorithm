package _des

import (
	"CryptoHashCode/utils"
	"crypto/cipher"
	"crypto/des"
)

/**
*将要加密的数据使用3des算法进行加密，并将密文返回
*/
func TripleDesEncrypt(data ,key []byte) ([]byte,error) {
	block,err:=des.NewTripleDESCipher(key)
	if err!=nil {
		return nil,err
	}
	//填充后的数据
    originData := utils.PkCS5EndPadding(data,block.BlockSize())
    //实例化加密模式
    mode := cipher.NewCBCEncrypter(block,key)
    //加密
    dst := make([]byte,len(originData))
    mode.CryptBlocks(dst,originData)
    return dst,nil
}
/**
*使用3des算法对密文进行解密并返回明文数据
*/
func TripleDesDecrypt(data ,key []byte) ([]byte,error) {
	block ,err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil,err
	}
	blockMode := cipher.NewCBCDecrypter(block,key)
	originData := make([]byte,len(data))
	blockMode.CryptBlocks(originData,data)
	return  originData,nil


}
