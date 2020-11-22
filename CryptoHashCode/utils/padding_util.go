package utils

import "bytes"

//为加密明文进行PCKS5尾部填充
func PkCS5EndPadding(data []byte, blockSize int) []byte {
	//1.计算要填充多少个
	size := blockSize - len(data)%blockSize
	//2.准备要填充多少个
	paddingText := bytes.Repeat([]byte{byte(size)}, size)
	//填充
	return append(data, paddingText...)
}

func ClearPACS5Padding(data []byte) []byte {
	clearSize := int(data[len(data)-1])
	return data[:len(data)-clearSize]
}

//为加密明文进行Zeros尾部填充
func ZerosEndPadding(data []byte, blockSize int) []byte {
	//1.计算要填充多少个
	size := blockSize - len(data)%blockSize
	//2.把0填入到数据中
	paddingText := bytes.Repeat([]byte{byte(0)}, size)
	return append(data, paddingText...)
}
func ClearZerosPadding(data []byte, blockSize int) []byte {
    size := blockSize - len(data)%blockSize
    return data[:len(data)-size]
}
