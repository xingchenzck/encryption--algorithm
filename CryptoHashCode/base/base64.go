package base

import "encoding/base64"

func Base64Encode(data []byte) []byte {
	//encoding := base64.NewEncoding()
	//base64.NewEncoder()
	encoding := base64.StdEncoding
	dst := make([]byte, encoding.EncodedLen(len(data)))
	encoding.Decode(dst, data)
	return dst
}
func Base64Decode(data string) []byte {
	encoding := base64.StdEncoding
	dst := make([]byte, encoding.EncodedLen(len(data)))
	encoding.Decode(dst, []byte(data))
	return dst
}
