package normalizer

import (
	"regexp"
	"strings"
)

const (
	CertPrefix    = "-----BEGIN CERTIFICATE-----"
	CertPostfix   = "-----END CERTIFICATE-----"
	SegmentLength = 65
)

var separators = regexp.MustCompile(`\r\n|\n|\r`)

// NormalizeCertBody нормализует тело сертификата в формате base64
func NormalizeCertBody(certBody string) string {
	if len(certBody) == 0 {
		return certBody
	}

	certBody = strings.TrimSpace(certBody)
	certBody = separators.ReplaceAllString(certBody, "")
	certBody = strings.TrimPrefix(certBody, CertPrefix)
	certBody = strings.TrimSuffix(certBody, CertPostfix)

	var segmentsCount int
	if len(certBody)%SegmentLength == 0 {
		segmentsCount = len(certBody) / SegmentLength
	} else {
		segmentsCount = (len(certBody) / SegmentLength) + 1
	}

	certSegments := make([]string, segmentsCount)
	for i := 0; i < len(certSegments); i++ {
		if i == len(certSegments)-1 {
			certSegments[i] = certBody[i*SegmentLength:]
		} else {
			certSegments[i] = certBody[i*SegmentLength : (i+1)*SegmentLength]
		}
	}

	certBody = strings.Join(certSegments, "\n")
	return CertPrefix + "\n" + certBody + "\n" + CertPostfix
}
