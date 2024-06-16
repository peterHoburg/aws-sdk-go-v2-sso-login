package aws_sdk_go_v2_sso_login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/pkg/browser"
	"gopkg.in/ini.v1"
)

type LoginInput struct {
	// ProfileName name of the profile in ~/.aws/config. [profile <ProfileName>]
	ProfileName string

	// LoginTimeout max time to wait for user to complete the SSO OIDC URL flow. This should be > 60 seconds.
	LoginTimeout time.Duration

	// Headed if true a browser will be opened with the URL for the SSO OIDC flow. You will have the [LoginTimeout] to
	// complete the flow in the browser.
	Headed bool

	// ForceLogin if true forces a new SSO OIDC flow even if the cached creds are still valid.
	ForceLogin bool
}

type configProfileStruct struct {
	name         string
	output       string
	region       string
	ssoAccountId string
	ssoRegion    string
	ssoRoleName  string
	ssoStartUrl  string
}

// TODO use sts to get caller id and check that the role creds work aws-sdk-go-v2-sso-login

// Login runs through the AWS CLI login flow if there isn't a ~/.aws/sso/cache file with valid creds. If ForceLogin is
// true then the login flow will always be triggered even if the cache is valid
func Login(ctx context.Context, params *LoginInput) (*aws.Config, *aws.Credentials, *aws.CredentialsCache, error) {

	configProfile, err := getConfigProfile(params.ProfileName)
	if err != nil {
		return nil, nil, nil, err
	}
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithSharedConfigProfile(configProfile.name),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getAwsCredsFromCache Failed to load aws credentials: %w", err)
	}

	var creds *aws.Credentials
	var credCache *aws.CredentialsCache
	err = nil

	if params.ForceLogin == false {
		creds, credCache, err = getAwsCredsFromCache(ctx, &cfg, configProfile)
	}
	if err != nil {
		_, err = ssoLoginFlow(ctx, &cfg, configProfile, params.Headed, params.LoginTimeout)
		if err != nil {
			return nil, nil, nil, err
		}
		creds, credCache, err = getAwsCredsFromCache(ctx, &cfg, configProfile)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	cacheFilePath, err := ssocreds.StandardCachedTokenFilepath(configProfile.ssoStartUrl)
	if err == nil {
		writeCacheFile(creds, cacheFilePath)
	}

	return &cfg, creds, credCache, nil
}

// writeCacheFile Writes the cache file that is read by the AWS CLI.
func writeCacheFile(creds *aws.Credentials, cacheFilePath string) {

	staticCredentials := aws.Credentials{
		AccessKeyID:     aws.ToString(&creds.AccessKeyID),
		SecretAccessKey: aws.ToString(&creds.SecretAccessKey),
		SessionToken:    aws.ToString(&creds.SessionToken),
		Expires:         time.UnixMilli(creds.Expires.UnixMilli()).UTC(),
		CanExpire:       true,
	}

	marshaledJson, err := json.Marshal(staticCredentials)
	if err != nil {
		return
	}

	err = os.WriteFile(cacheFilePath, marshaledJson, 744)
	if err != nil {
		return
	}

}

func getConfigProfile(profileName string) (*configProfileStruct, error) {
	defaultSharedConfigFilename := config.DefaultSharedConfigFilename()
	configFile, err := ini.Load(defaultSharedConfigFilename)

	sectionPrefix := "profile"

	if err != nil {
		return nil, fmt.Errorf("getProfile Failed to load shared config: %w", err)
	}
	configProfile := new(configProfileStruct)

	for _, section := range configFile.Sections() {
		sectionName := strings.TrimSpace(section.Name())

		if !strings.HasPrefix(strings.ToLower(sectionName), sectionPrefix) {
			// Not a profile section. We can skip it
			continue
		}
		computedProfileName := strings.TrimSpace(strings.TrimPrefix(sectionName, sectionPrefix))
		if computedProfileName != profileName {
			continue
		}

		configProfile.name = computedProfileName

		output := section.Key("output").Value()
		if output == "" {
			output = "json"
		}
		configProfile.output = output

		// There has to  be a better way to do the validation/error composition...
		profileErrorMsg := "getProfile Failed to find %s for profile %s in config file %s"

		region := section.Key("region").Value()
		if region == "" {
			return nil, fmt.Errorf(profileErrorMsg, "region", profileName, defaultSharedConfigFilename)
		}
		configProfile.region = region

		ssoAccountId := section.Key("sso_account_id").Value()
		if ssoAccountId == "" {
			return nil, fmt.Errorf(profileErrorMsg, "sso_account_id", profileName, defaultSharedConfigFilename)
		}
		configProfile.ssoAccountId = ssoAccountId

		ssoRegion := section.Key("sso_region").Value()
		if ssoRegion == "" {
			return nil, fmt.Errorf(profileErrorMsg, "sso_region", profileName, defaultSharedConfigFilename)
		}
		configProfile.ssoRegion = ssoRegion

		ssoRoleName := section.Key("sso_role_name").Value()
		if ssoRoleName == "" {
			return nil, fmt.Errorf(profileErrorMsg, "sso_role_name", profileName, defaultSharedConfigFilename)
		}
		configProfile.ssoRoleName = ssoRoleName

		ssoStartUrl := section.Key("sso_start_url").Value()
		if ssoStartUrl == "" {
			return nil, fmt.Errorf(profileErrorMsg, "sso_start_url", profileName, defaultSharedConfigFilename)
		}
		// The sso_start_url is required to have #/ at the end, or it breaks the cache lookup
		if !strings.HasSuffix(ssoStartUrl, "#/") {
			ssoStartUrl = ssoStartUrl + "#/"
		}
		configProfile.ssoStartUrl = ssoStartUrl
	}

	if configProfile.name == "" {
		return nil, fmt.Errorf("getProfile Failed to find profile %s in config file %s", profileName, defaultSharedConfigFilename)
	}
	return configProfile, nil

}

// getAwsCredsFromCache
func getAwsCredsFromCache(ctx context.Context, cfg *aws.Config, configProfile *configProfileStruct) (*aws.Credentials, *aws.CredentialsCache, error) {

	ssoClient := sso.NewFromConfig(*cfg)
	ssoOidcClient := ssooidc.NewFromConfig(*cfg)
	cachedTokenPath, err := ssocreds.StandardCachedTokenFilepath(configProfile.ssoStartUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("getAwsCredsFromCache Failed find cached token filepath for profile url %s: %w", configProfile.ssoStartUrl, err)
	}

	ssoCredsProvider := ssocreds.New(
		ssoClient,
		configProfile.ssoAccountId,
		configProfile.ssoRoleName,
		configProfile.ssoStartUrl,
		func(options *ssocreds.Options) {
			options.SSOTokenProvider = ssocreds.NewSSOTokenProvider(ssoOidcClient, cachedTokenPath)
		},
	)

	credCache := aws.NewCredentialsCache(ssoCredsProvider)
	creds, err := credCache.Retrieve(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getAwsCredsFromCache Failed to retrieve creds from ssoCredsProvider: %w", err)
	}
	return &creds, credCache, nil
}

func ssoLoginFlow(ctx context.Context, cfg *aws.Config, configProfile *configProfileStruct, headed bool, loginTimeout time.Duration) (*string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("ssoLoginFlow Failed to parse user: %w", err)
	}

	ssoOidcClient := ssooidc.NewFromConfig(*cfg)

	clientName := fmt.Sprintf("%s-%s-%s", currentUser, configProfile.name, configProfile.ssoRoleName)
	registerClient, err := ssoOidcClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String(clientName),
		ClientType: aws.String("public"),
		Scopes:     []string{"sso-portal:*"},
	})
	if err != nil {
		return nil, fmt.Errorf("ssoLoginFlow Failed to register ssoOidcClient: %w", err)
	}

	deviceAuth, err := ssoOidcClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     registerClient.ClientId,
		ClientSecret: registerClient.ClientSecret,
		StartUrl:     &configProfile.ssoStartUrl,
	})
	if err != nil {
		return nil, fmt.Errorf("ssoLoginFlow Failed to startDeviceAuthorization: %w", err)
	}

	authUrl := aws.ToString(deviceAuth.VerificationUriComplete)
	if headed == true {
		err = browser.OpenURL(authUrl)
		if err != nil {
			return nil, fmt.Errorf("ssoLoginFlow Failed to open browser: %w", err)
		}
	}
	token := new(ssooidc.CreateTokenOutput)
	tries := 10
	sleepPerCycle := loginTimeout / time.Duration(tries)
	for i := 0; i < tries; i++ {
		// Keep trying until the user approves the request in the browser
		token, err = ssoOidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     registerClient.ClientId,
			ClientSecret: registerClient.ClientSecret,
			DeviceCode:   deviceAuth.DeviceCode,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
		})
		if errors.Is(err, &types.AuthorizationPendingException{}) {
			time.Sleep(sleepPerCycle)
			continue
		} else if err != nil {
			return nil, fmt.Errorf("ssoLoginFlow Failed to create token: %w", err)
		}

		break
	}
	if err != nil {
		return nil, fmt.Errorf("ssoLoginFlow Failed to CreateToken: %w", err)
	}
	return token.AccessToken, nil
}