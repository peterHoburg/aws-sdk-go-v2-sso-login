package aws_sdk_go_v2_sso_login

import "fmt"

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
