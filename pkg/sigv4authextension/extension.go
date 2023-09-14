package sigv4authextension

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	sigv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension/auth"
	"go.uber.org/zap"
	grpcCredentials "google.golang.org/grpc/credentials"
)

// Sigv4Auth is a struct that implements the auth.Client interface.
// It provides the implementation for providing Sigv4 authentication for HTTP requests only.
type Sigv4Auth struct {
	cfg                    *Config
	logger                 *zap.Logger
	awsSDKInfo             string
	component.StartFunc    // embedded default behavior to do nothing with Start()
	component.ShutdownFunc // embedded default behavior to do nothing with Shutdown()
}

// compile time check that the Sigv4Auth struct satisfies the auth.Client interface
var _ auth.Client = (*Sigv4Auth)(nil)

// RoundTripper() returns a custom SigningRoundTripper.
func (sa *Sigv4Auth) RoundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	cfg := sa.cfg

	signer := sigv4.NewSigner()

	// Create the SigningRoundTripper struct
	rt := SigningRoundTripper{
		transport:     base,
		signer:        signer,
		region:        cfg.Region,
		service:       cfg.Service,
		credsProvider: cfg.credsProvider,
		awsSDKInfo:    sa.awsSDKInfo,
		logger:        sa.logger,
	}

	return &rt, nil
}

// PerRPCCredentials is implemented to satisfy the auth.Client interface but will not be implemented.
func (sa *Sigv4Auth) PerRPCCredentials() (grpcCredentials.PerRPCCredentials, error) {
	return nil, errors.New("Not Implemented")
}

// newSigv4Extension() is called by createExtension() in factory.go and
// returns a new Sigv4Auth struct.
func NewSigv4Extension(cfg *Config, logger *zap.Logger) *Sigv4Auth {
	awsSDKInfo := fmt.Sprintf("%s/%s", aws.SDKName, aws.SDKVersion)
	return &Sigv4Auth{
		cfg:        cfg,
		logger:     logger,
		awsSDKInfo: awsSDKInfo,
	}
}

// getCredsProviderFromConfig() is a helper function that gets AWS credentials
// from the Config.
func getCredsProviderFromConfig(cfg *Config) (*aws.CredentialsProvider, error) {
	awscfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(cfg.AssumeRole.STSRegion),
	)
	if err != nil {
		return nil, err
	}
	if cfg.AssumeRole.ARN != "" {
		stsSvc := sts.NewFromConfig(awscfg)

		provider := stscreds.NewAssumeRoleProvider(stsSvc, cfg.AssumeRole.ARN)
		awscfg.Credentials = aws.NewCredentialsCache(provider)
	}
	customAccessKey := os.Getenv("CUSTOM_AWS_ACCESS_KEY")
	customSecretKey := os.Getenv("CUSTOM_AWS_SECRET_ACCESS_KEY")
	if customAccessKey != "" && customSecretKey != "" {
		awscfg.Credentials = credentials.NewStaticCredentialsProvider(customAccessKey, customSecretKey, "")
	}
	_, err = awscfg.Credentials.Retrieve(context.Background())
	if err != nil {
		return nil, err
	}

	return &awscfg.Credentials, nil
}
