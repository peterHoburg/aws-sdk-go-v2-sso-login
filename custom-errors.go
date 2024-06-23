package aws_sdk_go_v2_sso_login

import "fmt"

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
	err            error
}

func NewLoadingConfigFileError(configFilePath string, err error) LoadingConfigFileError {
	return LoadingConfigFileError{configFilePath, err}
}

func (e LoadingConfigFileError) Error() string {
	return fmt.Sprintf("Failed to load config file: %s", e.ConfigFilePath)
}

func (e LoadingConfigFileError) Unwrap() error {
	return e.err
}

type MissingProfileError struct {
	ProfileName    string
	ConfigFilePath string
	err            error
}

func NewMissingProfileError(profileName string, configFilePath string, err error) MissingProfileError {
	return MissingProfileError{profileName, configFilePath, err}
}

func (e MissingProfileError) Error() string {
	return fmt.Sprintf("Profile %s does not exist in config file %s", e.ProfileName, e.ConfigFilePath)
}

func (e MissingProfileError) Unwrap() error {
	return e.err
}

// CacheFilepathGenerationError failed to generate a valid filepath for the given SSO start URL
type CacheFilepathGenerationError struct {
	ProfileName        string
	ProfileSSOStartURL string
	err                error
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
	return e.err
}
