// TODO use sts to get caller id and check that the role creds work
// TODO add tests
// TODO fix context.TODO()

package golang_aws_sdk_go_v2_cred_workflow

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"gopkg.in/ini.v1"
	"os/user"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/pkg/browser"
)

type ConfigProfile struct {
	name         string
	output       string
	region       string
	ssoAccountId string
	ssoRegion    string
	ssoRoleName  string
	ssoStartUrl  string
}

func GetCreds(ctx context.Context, profileName string, headed bool, loginTimeout time.Duration) (*aws.Credentials, error) {
	//Check the sso cache for the given profile to see if there is already a set of OIDC creds
	configProfile, err := getConfigProfile(profileName)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithSharedConfigProfile(configProfile.name),
	)
	if err != nil {
		return nil, fmt.Errorf("getAwsCredsFromCache Failed to load aws credentials: %w", err)
	}

	creds, err := getAwsCredsFromCache(ctx, &cfg, configProfile)
	if err != nil {
		_, err = ssoLoginFlow(&cfg, configProfile, headed, loginTimeout)
		if err != nil {
			return nil, err
		}
	}
	creds, err = getAwsCredsFromCache(ctx, &cfg, configProfile)
	if err != nil {
		return nil, err
	}
	return creds, nil
}

func getConfigProfile(profileName string) (*ConfigProfile, error) {
	defaultSharedConfigFilename := config.DefaultSharedConfigFilename()
	configFile, err := ini.Load(defaultSharedConfigFilename)

	sectionPrefix := "profile"

	if err != nil {
		return nil, fmt.Errorf("getProfile Failed to load shared config: %w", err)
	}
	configProfile := new(ConfigProfile)

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

func getAwsCredsFromCache(ctx context.Context, cfg *aws.Config, configProfile *ConfigProfile) (*aws.Credentials, error) {

	ssoClient := sso.NewFromConfig(*cfg)
	ssoOidcClient := ssooidc.NewFromConfig(*cfg)
	cachedTokenPath, err := ssocreds.StandardCachedTokenFilepath(configProfile.ssoStartUrl)
	if err != nil {
		return nil, fmt.Errorf("getAwsCredsFromCache Failed find cached token filepath for profile url %s: %w", configProfile.ssoStartUrl, err)
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

	creds, err := ssoCredsProvider.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("getAwsCredsFromCache Failed to retrieve creds from ssoCredsProvider: %w", err)
	}
	return &creds, nil
}

func ssoLoginFlow(cfg *aws.Config, configProfile *ConfigProfile, headed bool, loginTimeout time.Duration) (*string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("ssoLoginFlow Failed to parse user: %w", err)
	}

	ssoOidcClient := ssooidc.NewFromConfig(*cfg)

	clientName := fmt.Sprintf("%s-%s-%s", currentUser, configProfile.name, configProfile.ssoRoleName)
	registerClient, err := ssoOidcClient.RegisterClient(context.TODO(), &ssooidc.RegisterClientInput{
		ClientName: aws.String(clientName),
		ClientType: aws.String("public"),
		Scopes:     []string{"sso-portal:*"},
	})
	if err != nil {
		return nil, fmt.Errorf("ssoLoginFlow Failed to register ssoOidcClient: %w", err)
	}

	deviceAuth, err := ssoOidcClient.StartDeviceAuthorization(context.TODO(), &ssooidc.StartDeviceAuthorizationInput{
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
		token, err = ssoOidcClient.CreateToken(context.TODO(), &ssooidc.CreateTokenInput{
			ClientId:     registerClient.ClientId,
			ClientSecret: registerClient.ClientSecret,
			DeviceCode:   deviceAuth.DeviceCode,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
		})
		if err != nil {
			time.Sleep(sleepPerCycle)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("ssoLoginFlow Failed to CreateToken: %w", err)
	}
	return token.AccessToken, nil
}

func getRoleCreds(ctx context.Context, cfg *aws.Config, accessToken *string, configProfile *ConfigProfile) (*aws.Credentials, error) {
	ssoClient := sso.NewFromConfig(*cfg)

	creds, err := ssoClient.GetRoleCredentials(
		ctx,
		&sso.GetRoleCredentialsInput{
			AccessToken: accessToken,
			AccountId:   &configProfile.ssoAccountId,
			RoleName:    &configProfile.ssoRoleName,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("getRoleCreds failed to GetRoleCredentials %w", err)
	}
	awsCreds := aws.Credentials{
		AccessKeyID:     aws.ToString(creds.RoleCredentials.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.RoleCredentials.SecretAccessKey),
		SessionToken:    aws.ToString(creds.RoleCredentials.SessionToken),
		Expires:         time.UnixMilli(aws.ToInt64(&creds.RoleCredentials.Expiration)),
		CanExpire:       true,
	}
	return &awsCreds, nil
}
