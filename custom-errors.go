package aws_sdk_go_v2_sso_login

import (
	"fmt"
)

// ProfileValidationError error validating the given AWS profile. A required value may be missing.
type ProfileValidationError struct {
	ProfileName    string
	ConfigFilePath string
	FieldName      string
	CurrentValue   string
	ExpectedValue  string
}

func (e ProfileValidationError) Error() string {
	return fmt.Sprintf(
		"Profile validation failed. "+
			"Profile: %s "+
			"Config file path: %s "+
			"Field %s "+
			"Value: \"%s\" "+
			"Expected \"%s\"",
		e.ProfileName,
		e.ConfigFilePath,
		e.FieldName,
		e.CurrentValue,
		e.ExpectedValue,
	)
}

func NewProfileValidationError(profileName string, configFilePath string, fieldName string, currentValue string, expectedValue string) ProfileValidationError {
	return ProfileValidationError{profileName, configFilePath, fieldName, currentValue, expectedValue}
}

// LoadingConfigFileError failed to load the config file
type LoadingConfigFileError struct {
	ConfigFilePath string
	Err            error
}

func NewLoadingConfigFileError(configFilePath string, err error) LoadingConfigFileError {
	return LoadingConfigFileError{configFilePath, err}
}

func (e LoadingConfigFileError) Error() string {
	return fmt.Sprintf("Failed to load config file: %s", e.ConfigFilePath)
}

func (e LoadingConfigFileError) Unwrap() error {
	return e.Err
}

// MissingProfileError failed to find the requested profile
type MissingProfileError struct {
	ProfileName    string
	ConfigFilePath string
	Err            error
}

func NewMissingProfileError(profileName string, configFilePath string, err error) MissingProfileError {
	return MissingProfileError{profileName, configFilePath, err}
}

func (e MissingProfileError) Error() string {
	return fmt.Sprintf("Profile %s does not exist in config file %s", e.ProfileName, e.ConfigFilePath)
}

func (e MissingProfileError) Unwrap() error {
	return e.Err
}

// CacheFilepathGenerationError failed to generate a valid filepath for the given SSO start URL
type CacheFilepathGenerationError struct {
	ProfileName        string
	ProfileSSOStartURL string
	Err                error
}

func NewCacheFilepathGenerationError(ProfileName string, ProfileSSOStartURL string, err error) CacheFilepathGenerationError {
	return CacheFilepathGenerationError{ProfileName, ProfileSSOStartURL, err}
}

func (e CacheFilepathGenerationError) Error() string {
	return fmt.Sprintf(
		"Failed to generate cache file path for profile '%s' with URL %s",
		e.ProfileName,
		e.ProfileSSOStartURL,
	)
}

func (e CacheFilepathGenerationError) Unwrap() error {
	return e.Err
}

// ConfigFileLoadError failed to load default config
type ConfigFileLoadError struct {
	Err error
}

func (e ConfigFileLoadError) Error() string {
	return "failed to load default config"
}

func (e ConfigFileLoadError) Unwrap() error {
	return e.Err
}

// CredCacheError failed to retrieve creds from ssoCredsProvider
type CredCacheError struct {
	Err error
}

func (e CredCacheError) Error() string {
	return "failed to retrieve creds from ssoCredsProvider"
}

func (e CredCacheError) Unwrap() error {
	return e.Err
}

// OsUserError failed to retrieve user from osUser
type OsUserError struct {
	Err error
}

func (e OsUserError) Error() string {
	return "failed to retrieve user from osUser"
}

func (e OsUserError) Unwrap() error {
	return e.Err
}

// SsoOidcClientError Failed to register ssoOidcClient
type SsoOidcClientError struct {
	Err error
}

func (e SsoOidcClientError) Error() string {
	return "Failed to register ssoOidcClient"
}

func (e SsoOidcClientError) Unwrap() error {
	return e.Err
}

// StartDeviceAuthorizationError Failed to startDeviceAuthorization
type StartDeviceAuthorizationError struct {
	Err error
}

func (e StartDeviceAuthorizationError) Error() string {
	return "Failed to startDeviceAuthorization"
}

func (e StartDeviceAuthorizationError) Unwrap() error {
	return e.Err
}

// BrowserOpenError Failed to open a browser
type BrowserOpenError struct {
	Err error
}

func (e BrowserOpenError) Error() string {
	return "Failed to open a browser"
}

func (e BrowserOpenError) Unwrap() error {
	return e.Err
}

// SsoOidcTokenCreationError failed to retrieve user from osUser
type SsoOidcTokenCreationError struct {
	Err error
}

func (e SsoOidcTokenCreationError) Error() string {
	return "failed to retrieve user from osUser"
}

func (e SsoOidcTokenCreationError) Unwrap() error {
	return e.Err
}

// GetCallerIdError stsClient.GetCallerIdentity failed
type GetCallerIdError struct {
	Err error
}

func (e GetCallerIdError) Error() string {
	return "stsClient.GetCallerIdentity failed"
}

func (e GetCallerIdError) Unwrap() error {
	return e.Err
}

type CacheFileCreationError struct {
	Err           error
	Reason        string
	CacheFilePath string
}

func (e CacheFileCreationError) Error() string {
	return fmt.Sprintf("Cache file %s creation failed. Reason: %s", e.CacheFilePath, e.Reason)
}

func (e CacheFileCreationError) Unwrap() error {
	return e.Err
}
