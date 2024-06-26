package aws_sdk_go_v2_sso_login

import (
	"errors"
	"reflect"
	"testing"
)

func Test_getConfigProfile(t *testing.T) {
	type args struct {
		profileName    string
		configFilePath string
	}

	testConfLocation := "testdata/aws_configs"
	blankConfLocation := testConfLocation + "/blank"
	missingArgsConfLocation := testConfLocation + "/profiles.ini"

	tests := []struct {
		name           string
		args           args
		want           *configProfile
		wantErrorValue error
		ErrorAsType    any
	}{
		{
			name: "missing profile",
			args: args{
				profileName:    "",
				configFilePath: blankConfLocation,
			},
			want:           nil,
			wantErrorValue: NewMissingProfileError("", blankConfLocation, errors.New("")),
			ErrorAsType:    &MissingProfileError{},
		},
		{
			name: "missing region",
			args: args{
				profileName:    "missing_region",
				configFilePath: missingArgsConfLocation,
			},
			want:           nil,
			wantErrorValue: NewProfileValidationError("missing_region", missingArgsConfLocation, "region", "", "<non empty>"),
			ErrorAsType:    &ProfileValidationError{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := getConfigProfile(test.args.profileName, test.args.configFilePath)

			if (err != nil) && test.wantErrorValue == nil {
				t.Errorf("getConfigProfile() error = %v, wantErr %v", err, test.wantErrorValue)
				return
			}
			if (err != nil) && test.wantErrorValue != nil {
				if err.Error() != test.wantErrorValue.Error() {
					t.Errorf("getConfigProfile() error = %v, wantErr %v", err, test.wantErrorValue)
				}
				if test.ErrorAsType != nil {
					if !errors.As(err, test.ErrorAsType) {
						t.Errorf("getConfigProfile() error = %v, wantErr %v", err, test.ErrorAsType)
					}
				}
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("getConfigProfile() got = %v, want %v", got, test.want)
			}
		})
	}
}
