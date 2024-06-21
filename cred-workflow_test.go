package aws_sdk_go_v2_sso_login

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func Test_getConfigProfile(t *testing.T) {
	type args struct {
		profileName    string
		configFilePath string
	}
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	testConfLocation := exPath + "/test_data/aws_configs"
	blankConfLocation := testConfLocation + "/blank"
	missingArgsConfLocation := testConfLocation + "/profiles_missing_args"

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
			name: "missing name",
			args: args{
				profileName:    "missing_name",
				configFilePath: missingArgsConfLocation,
			},
			want:           nil,
			wantErr:        true,
			wantErrorValue: NewProfileValidationError("missing_name", missingArgsConfLocation, "name", "", ""),
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
				if !errors.Is(err, test.wantErrorValue) {
					t.Errorf("getConfigProfile() error = %v, wantErr %v", err, test.wantErrorValue)
				}
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("getConfigProfile() got = %v, want %v", got, test.want)
			}
		})
	}
}
