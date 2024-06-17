// Package aws_sdk_go_v2_sso_login THIS IS NOT AN OFFICIAL PART OF aws-sdk-go-v2. This was not created, or endorsed by
// Amazon, or AWS.
package aws_sdk_go_v2_sso_login

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

// IdentityResult contains the result of stsClient.GetCallerIdentity. If Identity is nul and error is not nul that
// can indicate that the credentials might be invalid.
type IdentityResult struct {
	Identity *sts.GetCallerIdentityOutput
	Error    error
}

type LoginOutput struct {
	Config           *aws.Config
	Credentials      *aws.Credentials
	CredentialsCache *aws.CredentialsCache
	IdentityResult   *IdentityResult
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

type cacheFileData struct {
	StartUrl              string    `json:"startUrl"`
	Region                string    `json:"region"`
	AccessToken           string    `json:"accessToken"`
	ExpiresAt             time.Time `json:"expiresAt"`
	ClientId              string    `json:"clientId"`
	ClientSecret          string    `json:"clientSecret"`
	RegistrationExpiresAt time.Time `json:"registrationExpiresAt"`
}

// Login runs through the AWS CLI login flow if there isn't a ~/.aws/sso/cache file with valid creds. If ForceLogin is
// true then the login flow will always be triggered even if the cache is valid
func Login(ctx context.Context, params *LoginInput) (*LoginOutput, error) {
	configProfile, err := getConfigProfile(params.ProfileName)
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

	var creds *aws.Credentials
	var credCache *aws.CredentialsCache
	var credCacheError error

	if params.ForceLogin == false {
		creds, credCache, credCacheError = getAwsCredsFromCache(ctx, &cfg, configProfile)
	}
	if credCacheError != nil {
		cacheFileData := cacheFileData{
			StartUrl:              configProfile.ssoStartUrl,
			Region:                configProfile.region,
			AccessToken:           "",
			ExpiresAt:             time.Time{},
			ClientId:              "",
			ClientSecret:          "",
			RegistrationExpiresAt: time.Time{},
		}
		_, err := ssoLoginFlow(ctx, &cacheFileData, &cfg, configProfile, params.Headed, params.LoginTimeout)
		if err != nil {
			return nil, err
		}

		//creds, err := getAwsCredsFromOidcToken(ctx, &cfg, token, *configProfile)
		//if err != nil {
		//	return nil, err
		//}

		cacheFilePath, err := ssocreds.StandardCachedTokenFilepath(configProfile.ssoStartUrl)
		if err != nil {
			return nil, err
		}

		err = writeCacheFile(cacheFileData, cacheFilePath)
		if err != nil {
			return nil, err
		}

	}
	creds, credCache, err = getAwsCredsFromCache(ctx, &cfg, configProfile)

	identity, err := getCallerID(ctx, &cfg)

	loginOutput := &LoginOutput{
		Config:           &cfg,
		Credentials:      creds,
		CredentialsCache: credCache,
		IdentityResult: &IdentityResult{
			Identity: identity,
			Error:    err,
		},
	}

	return loginOutput, nil
}

// writeCacheFile Writes the cache file that is read by the AWS CLI.
func writeCacheFile(cacheFileData cacheFileData, cacheFilePath string) error {
	marshaledJson, err := json.Marshal(cacheFileData)
	if err != nil {
		return fmt.Errorf("writeCacheFile failed to marshal json: %w", err)
	}
	dir, _ := path.Split(cacheFilePath)
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return fmt.Errorf("writeCacheFile failed to write dir %s: %w", dir, err)
	}

	err = os.WriteFile(cacheFilePath, marshaledJson, 0600)
	if err != nil {
		return fmt.Errorf("writeCacheFile failed to write file %s: %w", cacheFilePath, err)

	}
	return nil
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

func getAwsCredsFromOidcToken(ctx context.Context, cfg *aws.Config, oidcToken *string, configProfile configProfileStruct) (*aws.Credentials, error) {
	ssoClient := sso.NewFromConfig(*cfg)
	creds, err := ssoClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: oidcToken,
		AccountId:   &configProfile.ssoAccountId,
		RoleName:    &configProfile.ssoRoleName,
	})
	if err != nil {
		return nil, fmt.Errorf("getAwsCredsFromOidcToken failed to ssoClient.GetRoleCredentials: %w", err)
	}
	return &aws.Credentials{
		AccessKeyID:     *creds.RoleCredentials.AccessKeyId,
		SecretAccessKey: *creds.RoleCredentials.SecretAccessKey,
		SessionToken:    *creds.RoleCredentials.SessionToken,
		Source:          "",
		CanExpire:       true,
		Expires:         time.UnixMilli(creds.RoleCredentials.Expiration),
	}, nil
}
func ssoLoginFlow(ctx context.Context, cacheFileData *cacheFileData, cfg *aws.Config, configProfile *configProfileStruct, headed bool, loginTimeout time.Duration) (*string, error) {
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
	cacheFileData.ClientSecret = *registerClient.ClientSecret
	cacheFileData.ClientId = *registerClient.ClientId
	cacheFileData.RegistrationExpiresAt = time.Unix(registerClient.ClientSecretExpiresAt, 0).UTC()

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
		if err == nil {
			break
		}
		if strings.Contains(err.Error(), "AuthorizationPendingException") {
			time.Sleep(sleepPerCycle)
			continue
		}
		return nil, fmt.Errorf("ssoLoginFlow Failed to create token: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("ssoLoginFlow Failed to CreateToken: %w", err)
	}
	cacheFileData.AccessToken = *token.AccessToken
	cacheFileData.ExpiresAt = time.Unix(time.Now().Unix()+int64(token.ExpiresIn), 0).UTC()
	return token.AccessToken, nil
}

func getCallerID(ctx context.Context, cfg *aws.Config) (*sts.GetCallerIdentityOutput, error) {
	stsClient := sts.NewFromConfig(*cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("getCallerID failed to stsClient.GetCallerIdentity: %w", err)
	}
	return identity, nil
}
