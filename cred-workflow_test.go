package aws_sdk_go_v2_sso_login

import (
	"os"
	"reflect"
	"testing"
)

func Test_getConfigProfile(t *testing.T) {
	type args struct {
		profileName    string
		configFilePath string
	}
	tempFile, err := os.CreateTemp("", "tempProfiles")
	if err != nil {
		t.Errorf("Error creating temp profile file: %v", err)
	}

	defer os.Remove(tempFile.Name()) // clean up

	tests := []struct {
		name           string
		args           args
		want           *configProfile
		wantErr        bool
		wantErrorValue error
		fileValue      string
	}{
		{
			name: "empty profile",
			args: args{
				profileName:    "",
				configFilePath: tempFile.Name(),
			},
			want:           nil,
			wantErr:        true,
			wantErrorValue: NewProfileValidationError("", "", "", "", ""),
			fileValue:      "",
		},
	}
	for _, test := range tests {
		_, tempFileWriteError := tempFile.Write([]byte(test.fileValue))

		t.Run(test.name, func(t *testing.T) {
			if tempFileWriteError != nil {
				t.Errorf("Failed to write temp file: %v", tempFileWriteError)
			}

			got, err := getConfigProfile(test.args.profileName, test.args.configFilePath)

			if (err != nil) != test.wantErr {
				t.Errorf("getConfigProfile() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if (err != nil) && test.wantErr {
				if err != test.wantErrorValue {
					t.Errorf("getConfigProfile() error = %v, wantErr %v", err, test.wantErrorValue)
				}
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("getConfigProfile() got = %v, want %v", got, test.want)
			}
		})
	}
}
