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

// TODO update docs at the top of the file for SEO
// TODO more tests
// TODO more custom errors.
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

type configProfile struct {
	name         string
	output       string
	region       string
	ssoAccountId string
	ssoRegion    string
	ssoRoleName  string
	ssoStartUrl  string
}

func (v *configProfile) validate(profileName string, configFilePath string) error {
	if v.name == "" {
		return NewProfileValidationError(profileName, configFilePath, "name", v.name, "<non empty>")
	}
	if v.output == "" {
		v.output = "json"
	}
	if v.region == "" {
		return NewProfileValidationError(profileName, configFilePath, "region", v.region, "<non empty>")
	}
	if v.ssoAccountId == "" {
		return NewProfileValidationError(profileName, configFilePath, "sso_account_id", v.ssoAccountId, "<non empty>")
	}
	if v.ssoRegion == "" {
		return NewProfileValidationError(profileName, configFilePath, "sso_region", v.ssoRegion, "<non empty>")
	}
	if v.ssoRoleName == "" {
		return NewProfileValidationError(profileName, configFilePath, "sso_role_name", v.ssoRoleName, "<non empty>")
	}
	if v.ssoStartUrl == "" {
		return NewProfileValidationError(profileName, configFilePath, "sso_start_url", v.ssoStartUrl, "<non empty>")
	}
	return nil
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
	var creds *aws.Credentials
	var credCache *aws.CredentialsCache
	var credCacheError error

	configFilePath := config.DefaultSharedConfigFilename()
	profile, err := getConfigProfile(params.ProfileName, configFilePath)
	if err != nil {
		return nil, err
	}

	cacheFilePath, err := ssocreds.StandardCachedTokenFilepath(profile.ssoStartUrl)
	if err != nil {
		return nil, NewCacheFilepathGenerationError(profile.name, profile.ssoStartUrl, err)
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile.name))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ConfigFileLoadError, err)
	}

	// This does not need to be run if ForceLogin is set, but doing it simplifies the overall flow, and is still fast.
	creds, credCache, credCacheError = getAwsCredsFromCache(ctx, &cfg, profile, cacheFilePath)
	identity, callerIDError := getCallerID(ctx, &cfg)

	// Creds are invalid, try logging in again
	if credCacheError != nil || callerIDError != nil || params.ForceLogin == true {
		cacheFile, err := ssoLoginFlow(ctx, &cfg, profile, params.Headed, params.LoginTimeout)
		if err != nil {
			return nil, err
		}

		err = writeCacheFile(cacheFile, cacheFilePath)
		if err != nil {
			return nil, err
		}

		creds, credCache, credCacheError = getAwsCredsFromCache(ctx, &cfg, profile, cacheFilePath)
		if credCacheError != nil {
			return nil, credCacheError
		}

		identity, callerIDError = getCallerID(ctx, &cfg)
	}

	loginOutput := &LoginOutput{
		Config:           &cfg,
		Credentials:      creds,
		CredentialsCache: credCache,
		IdentityResult: &IdentityResult{
			Identity: identity,
			Error:    callerIDError,
		},
	}

	return loginOutput, nil
}

// writeCacheFile Writes the cache file that is read by the AWS CLI.
func writeCacheFile(cacheFileData *cacheFileData, cacheFilePath string) error {
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

func getConfigProfile(profileName string, configFilePath string) (*configProfile, error) {
	var profile configProfile
	sectionPrefix := "profile"

	configFile, err := ini.Load(configFilePath)

	if err != nil {
		return nil, NewLoadingConfigFileError(configFilePath, err)
	}

	for _, section := range configFile.Sections() {
		sectionName := strings.TrimSpace(section.Name())

		if !strings.HasPrefix(strings.ToLower(sectionName), sectionPrefix) {
			// Not a profile section. We can skip it
			continue
		}
		trimmedProfileName := strings.TrimSpace(strings.TrimPrefix(sectionName, sectionPrefix))
		if trimmedProfileName != profileName {
			continue
		}
		profile = configProfile{
			name:         trimmedProfileName,
			output:       section.Key("output").Value(),
			region:       section.Key("region").Value(),
			ssoAccountId: section.Key("sso_account_id").Value(),
			ssoRegion:    section.Key("sso_region").Value(),
			ssoRoleName:  section.Key("sso_role_name").Value(),
			ssoStartUrl:  section.Key("sso_start_url").Value(),
		}

		// The sso_start_url is required to have #/ at the end, or it breaks the cache lookup
		if !strings.HasSuffix(profile.ssoStartUrl, "#/") {
			profile.ssoStartUrl = profile.ssoStartUrl + "#/"
		}
		err = profile.validate(profileName, configFilePath)
		if err != nil {
			return nil, err
		}
	}

	// Checks to see if a profile was found
	if profile.name == "" {
		return nil, NewMissingProfileError(profileName, configFilePath, err)
	}
	return &profile, nil
}

// getAwsCredsFromCache
func getAwsCredsFromCache(
	ctx context.Context,
	cfg *aws.Config,
	profile *configProfile,
	cacheFilePath string,
) (*aws.Credentials, *aws.CredentialsCache, error) {
	ssoClient := sso.NewFromConfig(*cfg)
	ssoOidcClient := ssooidc.NewFromConfig(*cfg)

	ssoCredsProvider := ssocreds.New(
		ssoClient,
		profile.ssoAccountId,
		profile.ssoRoleName,
		profile.ssoStartUrl,
		func(options *ssocreds.Options) {
			options.SSOTokenProvider = ssocreds.NewSSOTokenProvider(ssoOidcClient, cacheFilePath)
		},
	)

	credCache := aws.NewCredentialsCache(ssoCredsProvider)
	creds, err := credCache.Retrieve(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", CredCacheError, err)
	}
	return &creds, credCache, nil
}

func getAwsCredsFromOidcToken(
	ctx context.Context,
	cfg *aws.Config,
	oidcToken *string,
	configProfile configProfile,
) (*aws.Credentials, error) {
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

func ssoLoginFlow(
	ctx context.Context,
	cfg *aws.Config,
	profile *configProfile,
	headed bool,
	loginTimeout time.Duration,
) (*cacheFileData, error) {
	ssoOidcClient := ssooidc.NewFromConfig(*cfg)

	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("ssoLoginFlow Failed to parse user: %w", err)
	}

	clientName := fmt.Sprintf("%s-%s-%s", currentUser, profile.name, profile.ssoRoleName)
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
		StartUrl:     &profile.ssoStartUrl,
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
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "Open the following URL in your browser: %s\n", authUrl)
	}

	var createTokenErr error
	token := new(ssooidc.CreateTokenOutput)
	sleepPerCycle := 2 * time.Second
	startTime := time.Now()
	delta := time.Now().Sub(startTime)

	for delta < loginTimeout {
		// Keep trying until the user approves the request in the browser
		token, createTokenErr = ssoOidcClient.CreateToken(
			ctx, &ssooidc.CreateTokenInput{
				ClientId:     registerClient.ClientId,
				ClientSecret: registerClient.ClientSecret,
				DeviceCode:   deviceAuth.DeviceCode,
				GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
			},
		)
		if createTokenErr == nil {
			break
		}
		if strings.Contains(createTokenErr.Error(), "AuthorizationPendingException") {
			time.Sleep(sleepPerCycle)
			delta = time.Now().Sub(startTime)
			continue
		}
	}
	// Checks to see if there is a valid token after the login timeout ends
	if createTokenErr != nil {
		return nil, fmt.Errorf("ssoLoginFlow Failed to CreateToken: %w", createTokenErr)
	}
	cacheFile := cacheFileData{
		StartUrl:              profile.ssoStartUrl,
		Region:                profile.region,
		AccessToken:           *token.AccessToken,
		ExpiresAt:             time.Unix(time.Now().Unix()+int64(token.ExpiresIn), 0).UTC(),
		ClientSecret:          *registerClient.ClientSecret,
		ClientId:              *registerClient.ClientId,
		RegistrationExpiresAt: time.Unix(registerClient.ClientSecretExpiresAt, 0).UTC(),
	}

	return &cacheFile, nil
}

func getCallerID(ctx context.Context, cfg *aws.Config) (*sts.GetCallerIdentityOutput, error) {
	stsClient := sts.NewFromConfig(*cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("getCallerID failed to stsClient.GetCallerIdentity: %w", err)
	}
	return identity, nil
}
