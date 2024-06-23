package aws_sdk_go_v2_sso_login

import (
	"errors"
	"fmt"
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
		wantErr        bool
		wantErrorValue error
	}{
		{
			name: "missing profile",
			args: args{
				profileName:    "",
				configFilePath: blankConfLocation,
			},
			want:           nil,
			wantErr:        true,
			wantErrorValue: errors.New(fmt.Sprintf("getProfile Failed to find profile %s in config file %s", "", blankConfLocation)),
		},
		{
			name: "missing region",
			args: args{
				profileName:    "missing_region",
				configFilePath: missingArgsConfLocation,
			},
			want:           nil,
			wantErr:        true,
			wantErrorValue: NewProfileValidationError("missing_region", missingArgsConfLocation, "region", "", "<non empty>"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := getConfigProfile(test.args.profileName, test.args.configFilePath)

			if (err != nil) != test.wantErr {
				t.Errorf("getConfigProfile() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if (err != nil) && test.wantErr {
				if err.Error() != test.wantErrorValue.Error() {
					t.Errorf("getConfigProfile() error = %v, wantErr %v", err, test.wantErrorValue)
				}
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("getConfigProfile() got = %v, want %v", got, test.want)
			}
		})
	}
}
