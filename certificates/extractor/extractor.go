package extractor

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"go.mozilla.org/pkcs7"
)

type ExtractParams struct {
	b64encoded bool
}

type ExtractOption func(*ExtractParams)

// WithB64Encoded позволяет указать, что входные данные закодированы в base64
func WithB64Encoded() ExtractOption {
	return func(params *ExtractParams) {
		params.b64encoded = true
	}
}

// ExtractCertFromPKCS7 извелкает тело сертификата подписанта в формате PEM из PKCS#7 подписи
func ExtractCertFromPKCS7(value []byte, opts ...ExtractOption) ([]byte, error) {
	const operation = "certificates.extractor.ExportCertFromPKCS7"

	params := &ExtractParams{
		b64encoded: false,
	}
	for _, opt := range opts {
		opt(params)
	}

	var content []byte

	if params.b64encoded {
		var err error
		content, err = decodeBase64(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", operation, err)
		}
	} else {
		content = value
	}

	sign, err := pkcs7.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("%s: parse #PKCS7 error: %v", operation, err)
	}

	cert := sign.GetOnlySigner()

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(block), nil
}

// decodeBase64 декодирует данные в base64
func decodeBase64(value []byte) ([]byte, error) {
	const operation = "certificates.extractor.decodeBase64"

	content := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	_, err := base64.StdEncoding.Decode(content, value)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", operation, err)
	}
	return content, nil
}
