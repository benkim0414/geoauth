package internal

import (
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const awsRegion = "us-east-1"

// DecryptSecret converts the encrypted client secret to password string.
func DecryptSecret(secret string) (string, error) {
	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		panic("failed to load config, " + err.Error())
	}

	// Set the AWS Region that the service clients should use
	cfg.Region = endpoints.UsEast1RegionID

	svc := kms.New(cfg)
	blob, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	req := svc.DecryptRequest(&kms.DecryptInput{
		CiphertextBlob: blob,
	})
	result, err := req.Send()
	if err != nil {
		return "", err
	}
	return string(result.Plaintext), nil
}
