package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"emperror.dev/errors"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/hashicorp/vault/command/agent/auth/alicloud"
	"github.com/hashicorp/vault/command/agent/auth/approle"
	"github.com/hashicorp/vault/command/agent/auth/aws"
	"github.com/hashicorp/vault/command/agent/auth/azure"
	"github.com/hashicorp/vault/command/agent/auth/cert"
	"github.com/hashicorp/vault/command/agent/auth/cf"
	"github.com/hashicorp/vault/command/agent/auth/gcp"
	"github.com/hashicorp/vault/command/agent/auth/jwt"
	"github.com/hashicorp/vault/command/agent/auth/kerberos"
	"github.com/hashicorp/vault/command/agent/auth/kubernetes"
	agentConfig "github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/sink"
	"github.com/hashicorp/vault/command/agent/sink/file"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/oklog/run"
	"github.com/spf13/viper"
)

// nolint: gochecknoinits
func init() {
	//remote.RegisterConfigProvider("vault", NewConfigProvider())
}

// ConfigProvider implements reads configuration from Hashicorp Vault.
type vaultProvider struct {
	client *api.Client
}

// VaultConfig provides the user a configuration struct for vault token acqusition.
type Options struct {
	AuthMethodType   string
	AuthMethodConfig map[string]interface{}
	Namespace        string
	TokenMountPath   string
}

func (o Options) ToAutoAuthConfig() *agentConfig.AutoAuth {
	return &agentConfig.AutoAuth{
		Method: &agentConfig.Method{
			Type:      o.AuthMethodType,
			Namespace: o.Namespace,
			Config:    o.AuthMethodConfig,
			MountPath: "auth/kubernetes",
		},
		Sinks: []*agentConfig.Sink{{
			Type: "file",
			Config: map[string]interface{}{
				"path": o.TokenMountPath,
			},
		},
		},
	}
}

// NewConfigProvider returns a new ConfigProvider.
func NewConfigProvider(o *Options) *vaultProvider {
	clientConfig := api.DefaultConfig()
	if err := clientConfig.ReadEnvironment(); err != nil {
		panic(errors.Wrap(err, "failed to read environment"))
	}
	client, err := api.NewClient(clientConfig)
	if err != nil {
		panic(errors.WrapIf(err, "failed to create vault api client"))
	}
	config := o.ToAutoAuthConfig()
	// ctx and cancelFunc are passed to the AuthHandler, SinkServer, and
	// TemplateServer that periodically listen for ctx.Done() to fire and shut
	// down accordingly.
	ctx, cancelFunc := context.WithCancel(context.Background())
	logger := logging.NewVaultLoggerWithWriter(os.Stdout, log.Trace)
	var method auth.AuthMethod
	var sinks []*sink.SinkConfig
	if config != nil {
		for _, sc := range config.Sinks {
			switch sc.Type {
			case "file":
				config := &sink.SinkConfig{
					Logger:    logger.Named("sink.file"),
					Config:    sc.Config,
					Client:    client,
					WrapTTL:   sc.WrapTTL,
					DHType:    sc.DHType,
					DeriveKey: sc.DeriveKey,
					DHPath:    sc.DHPath,
					AAD:       sc.AAD,
				}
				s, err := file.NewFileSink(config)
				if err != nil {
					fmt.Printf("Error creating file sink: %s", err)
				}
				config.Sink = s
				sinks = append(sinks, config)
			default:
				fmt.Printf("Unknown sink type %q", sc.Type)
			}
		}
		mountPath := config.Method.MountPath

		authConfig := &auth.AuthConfig{
			Logger:    logger.Named(fmt.Sprintf("auth.%s", config.Method.Type)),
			MountPath: mountPath,
			Config:    config.Method.Config,
		}
		var err error
		switch config.Method.Type {
		case "alicloud":
			method, err = alicloud.NewAliCloudAuthMethod(authConfig)
		case "aws":
			method, err = aws.NewAWSAuthMethod(authConfig)
		case "azure":
			method, err = azure.NewAzureAuthMethod(authConfig)
		case "cert":
			method, err = cert.NewCertAuthMethod(authConfig)
		case "cf":
			method, err = cf.NewCFAuthMethod(authConfig)
		case "gcp":
			method, err = gcp.NewGCPAuthMethod(authConfig)
		case "jwt":
			method, err = jwt.NewJWTAuthMethod(authConfig)
		case "kerberos":
			method, err = kerberos.NewKerberosAuthMethod(authConfig)
		case "kubernetes":
			method, err = kubernetes.NewKubernetesAuthMethod(authConfig)
		case "approle":
			method, err = approle.NewApproleAuthMethod(authConfig)
		case "pcf": // Deprecated.
			method, err = cf.NewCFAuthMethod(authConfig)
		default:
			fmt.Printf("Unknown auth method %q", config.Method.Type)
		}
		if err != nil {
			fmt.Printf("Error creating %s auth method: {{err}}", config.Method.Type)
		}
	}

	// Start auto-auth and sink servers
	if method != nil {
		ah := auth.NewAuthHandler(&auth.AuthHandlerConfig{
			Logger:                       logger.Named("auth.handler"),
			Client:                       client,
			WrapTTL:                      config.Method.WrapTTL,
			EnableReauthOnNewCredentials: config.EnableReauthOnNewCredentials,
			EnableTemplateTokenCh:        true,
		})

		ss := sink.NewSinkServer(&sink.SinkServerConfig{
			Logger:        logger.Named("sink.server"),
			Client:        client,
			ExitAfterAuth: false,
		})

		var g run.Group

		// This run group watches for signal termination
		g.Add(func() error {
			return ah.Run(ctx, method)
		}, func(error) {
			// Let the lease cache know this is a shutdown; no need to evict
			// everything
			cancelFunc()
		})

		g.Add(func() error {
			err := ss.Run(ctx, ah.OutputCh, sinks)
			logger.Info("sinks finished, exiting")

			// Start goroutine to drain from ah.OutputCh from this point onward
			// to prevent ah.Run from being blocked.
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-ah.OutputCh:
					}
				}
			}()

			return err
		}, func(error) {
			// Let the lease cache know this is a shutdown; no need to evict
			// everything
			cancelFunc()
		})

		go ah.Run(ctx, method)
		go ss.Run(ctx, ah.OutputCh, sinks)

		token := <-ah.OutputCh

		client.SetToken(token)

	}

	return &vaultProvider{
		client: client,
	}
}

func (p vaultProvider) Get(rp viper.RemoteProvider) (io.Reader, error) {
	secret, err := p.client.Logical().Read(rp.Path())
	if err != nil {
		return nil, errors.WrapIf(err, "failed to read secret")
	}

	if secret == nil {
		return nil, errors.Errorf("source not found: %s", rp.Path())
	}

	if secret.Data == nil && secret.Warnings != nil {
		return nil, errors.Errorf("source: %s errors: %v", rp.Path(), secret.Warnings)
	}

	secretData := secret.Data
	if _, hasMetadata := secret.Data["metadata"]; hasMetadata {
		if secretV2, found := secret.Data["data"].(map[string]interface{}); found {
			secretData = secretV2
		}
	}
	b, err := json.Marshal(secretData)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to json encode secret")
	}

	return bytes.NewReader(b), nil
}

func (p vaultProvider) Watch(rp viper.RemoteProvider) (io.Reader, error) {
	b, err := p.Get(rp)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (p vaultProvider) WatchChannel(rp viper.RemoteProvider) (<-chan *viper.RemoteResponse, chan bool) {
	panic("watch channel is not implemented for the vault config provider")
}
