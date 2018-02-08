package internal

import (
	"encoding/base64"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

const awsRegion = "us-east-1"

// DecryptSecret converts the encrypted client secret to password string.
func DecryptSecret(secret string) (string, error) {
	kc := kms.New(session.New(), aws.NewConfig().WithRegion(awsRegion))
	blob, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	output, err := kc.Decrypt(&kms.DecryptInput{
		CiphertextBlob: blob,
	})
	if err != nil {
		return "", err
	}
	return string(output.Plaintext), nil
}
