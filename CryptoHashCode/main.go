package main

import (
	"CryptoHashCodeClass3/des"
	"fmt"
	"CryptoHashCodeClass3/3des"
	"CryptoHashCodeClass3/aes"
	"CryptoHashCodeClass3/rsa"
	"CryptoHashCodeClass3/ecc"
	"CryptoHashCodeClass3/base"
)

func main() {
	/**
	 * DES三元素：key、data、mode
	 *
	 */
	//一、发动端加密
	//key := []byte("C1906031") //密钥
	//data := "ab"

	//block, err := des.NewCipher(key)
	//if err != nil {
	//	panic(err.Error())
	//}
	//
	////计算需要填充多少
	//paddingSize := block.BlockSize() - len([]byte(data))%block.BlockSize()
	////padding：内边距, 填充
	//paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	////填充后的明文数据
	//dataText := append([]byte(data), paddingText...)

	//cryptoText := make([]byte, len([]byte(dataText)))
	//block.Encrypt(cryptoText,dataText)
	//fmt.Println(cryptoText)

	//mode := cipher.NewCBCEncrypter(block, key)
	//dst := make([]byte, len([]byte(dataText)))
	//mode.CryptBlocks(dst, []byte(dataText))
	//fmt.Println("加密后的内容：", string(dst))
	//
	////二、接收端解密
	////DES解密：密钥、密文数据、模式
	//key1 := []byte("C1906031")
	//
	//block1, err := des.NewCipher(key1)
	//if err != nil {
	//	panic(err.Error())
	//}
	//
	////密文数据
	//cipherData := dst

	//实例化一个解密模式实例
	//blockMode1 := cipher.NewCBCDecrypter(block1,key1)
	//
	//创建明文容器
	//originalData := make([]byte, len(cipherData))
	////解密
	//blockMode1.CryptBlocks(originalData,cipherData)
	//fmt.Println("解密后的内容：",string(originalData))

	//一、des算法:key、data
	key := []byte("20201112") //des秘钥长度：8
	data := "穷在闹市无人问，富在深山有远亲"

	//1、加密
	cipherText, err := des.DESEnCrypt([]byte(data), key)
	if err != nil {
		fmt.Println("加密失败：", err.Error())
		return
	}
	//2、解密
	originalText, err := des.DESDeCrypt(cipherText, key)
	if err != nil {
		fmt.Println("解密失败：", err.Error())
		return
	}
	fmt.Println("DES解密结果：", string(originalText))

	//二、3DES算法
	key1 := []byte("202011122020111220201112") //3des密钥长度必须为24字节
	data1 := "窗含西岭千秋雪，门泊东吴万里船"

	cipherText1, err := _des.TripleDesEncrypt([]byte(data1), key1)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	originalText1, err := _des.TripleDesDecrypt(cipherText1, key1)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("3DES算法解密后的内容：", string(originalText1))

	//3、AES算法
	//AES算法密钥长度：16字节、24字节、32字节
	//16->128位  24->192位  32->256位
	key2 := []byte("20201112202011122020111220201112") //8

	data2 := "只是因为在人群中多看了你一眼，再也没能忘记你容颜"
	cipherText2, err := aes.AESEncrypt([]byte(data2), key2)
	if err != nil {
		//crypto/aes: invalid key size 8
		fmt.Println(err.Error())
		return
	}
	fmt.Println("AES算法加密后的内容:", string(cipherText2))

	//4、RSA算法
	fmt.Println("=================RSA算法======================")
	//data4 := "在天愿做比翼鸟，在地愿为连理枝"
	//4.1 生成一对秘钥
	//pri, err := rsa.CreateRSAKey()
	//if err != nil {
	//	fmt.Println("rsa算法秘钥生成失败:", err.Error())
	//	return
	//}

	//4.1.5 将私钥保存到文件中
	err = rsa.GenerateKeysPem("xw")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	//4.2 使用生成的秘钥对数据进行加密
	//cipherText4, err := rsa.RSAEncrypt(pri.PublicKey, []byte(data4))
	//if err != nil {
	//	fmt.Println("rsa算法加密失败：", err.Error())
	//	return
	//}
	//
	////4.3 使用私钥进行解密
	//originalText4, err := rsa.RSADecrypt(pri, cipherText4)
	//if err != nil {
	//	fmt.Println(err.Error())
	//	return
	//}
	//fmt.Println("rsa算法解密成功：", string(originalText4))
	//
	////4.4 使用rsa算法对数据进行签名
	//signText4, err := rsa.RSASign(pri, []byte(data4))
	//if err != nil {
	//	fmt.Println("rsa算法签名失败：", err.Error())
	//	return
	//}
	//
	////4.5 使用rsa公钥对签名进行验证
	//data4 = "在天愿做比翼鸟，在地愿为连理枝。"
	//verifyResult, err := rsa.RSAVerify(pri.PublicKey, []byte(data4), signText4)
	//if err != nil {
	//	fmt.Println("rsa签名验证失败:", err.Error())
	//}
	//if verifyResult {
	//	fmt.Println("恭喜，rsa签名验证成功!")
	//} else {
	//	fmt.Println("抱歉，rsa签名验证失败!")
	//}

	//5、ecc算法中ecdsa数据签名算法
	priKey, err := ecc.GenerateKey()
	if err != nil {
		fmt.Println("ecdsa生成密钥错误：", err.Error())
		return
	}
	data5 := "小妹妹送我的郎，送到了我的房"
	r, s, err := ecc.ECDSASign(priKey, []byte(data5))
	if err != nil {
		fmt.Println("签名错误：", err.Error())
		return
	}
	verifyResult := ecc.ECDSAVerify(priKey.PublicKey, r, s, []byte(data5))
	if verifyResult {
		fmt.Println("签名验证成功")
	} else {
		fmt.Println("签名验证失败")
	}

	//6、base64编解码
	fmt.Println("===============BASE64编解码===================")
	data6 := "hello world"
	encodeBytes := base.Base64Encode([]byte(data6))
	decodeBytes := base.Base64Decode(encodeBytes)
	fmt.Println(string(decodeBytes))
}
