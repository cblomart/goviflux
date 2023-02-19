package vicare

import (
	"github.com/billgraziano/dpapi"
)

func TokenDecrypt(encryptedToken string) string {
	t, err := dpapi.Decrypt(encryptedToken)
	if err != nil {
		return ""
	}
	return t
}

func TokenEncrypt(token string) string {
	et, err := dpapi.Encrypt(token)
	if err != nil {
		return ""
	}
	return et
}
