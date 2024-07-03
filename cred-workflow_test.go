package aws_sdk_go_v2_sso_login

import (
	"errors"
	"os"
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
	ssoSessionConfLocation := testConfLocation + "/sso_session_profiles.ini"
	defaultOptionsConfLocation := testConfLocation + "/default_options.ini"

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
		{
			name: "complete profile",
			args: args{
				profileName:    "complete",
				configFilePath: missingArgsConfLocation,
			},
			want: &configProfile{
				name:         "complete",
				output:       "output",
				region:       "us-west-2",
				ssoAccountId: "sso_account_id",
				ssoRegion:    "sso_region",
				ssoRoleName:  "sso_role_name",
				ssoStartUrl:  "https://my-sso-portal.awsapps.com/start#/",
			},
			wantErrorValue: nil,
			ErrorAsType:    nil,
		},
		{
			name: "sso session profile",
			args: args{
				profileName:    "session-test",
				configFilePath: ssoSessionConfLocation,
			},
			want: &configProfile{
				name:         "session-test",
				output:       "json",
				region:       "us-west-2",
				ssoAccountId: "123456789011",
				ssoRegion:    "us-east-1",
				ssoRoleName:  "readOnly",
				ssoStartUrl:  "https://my-sso-portal.awsapps.com/start#/",
				ssoSession:   "my-sso",
			},
			wantErrorValue: nil,
			ErrorAsType:    nil,
		},
		{
			name: "default and sso session profile",
			args: args{
				profileName:    "session-test",
				configFilePath: defaultOptionsConfLocation,
			},
			want: &configProfile{
				name:         "session-test",
				output:       "json",
				region:       "us-west-2",
				ssoAccountId: "123456789011",
				ssoRegion:    "us-east-1",
				ssoRoleName:  "readOnly",
				ssoStartUrl:  "https://my-sso-portal.awsapps.com/start#/",
				ssoSession:   "my-sso",
			},
			wantErrorValue: nil,
			ErrorAsType:    nil,
		},
		{
			name: "default should not override",
			args: args{
				profileName:    "defaults-should-not-override",
				configFilePath: defaultOptionsConfLocation,
			},
			want: &configProfile{
				name:         "defaults-should-not-override",
				output:       "output",
				region:       "region",
				ssoAccountId: "sso_account_id",
				ssoRegion:    "sso_region",
				ssoRoleName:  "sso_role_name",
				ssoStartUrl:  "https://my-sso-portal.awsapps.com/start#/",
			},
			wantErrorValue: nil,
			ErrorAsType:    nil,
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

func Test_getCacheFilePath(t *testing.T) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	type args struct {
		profile *configProfile
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "sso session",
			args: args{
				profile: &configProfile{
					name:         "name",
					output:       "output",
					region:       "region",
					ssoAccountId: "ssoAccountId",
					ssoRegion:    "ssoRegion",
					ssoRoleName:  "ssoRoleName",
					ssoStartUrl:  "ssoStartUrl",
					ssoSession:   "ssoSession",
				},
			},
			want:    userHomeDir + "/.aws/sso/cache/1d52a0edb1889e4c71c2ee4839982f54d39d1773.json",
			wantErr: false,
		},
		{
			name: "no sso session",
			args: args{
				profile: &configProfile{
					name:         "name",
					output:       "output",
					region:       "region",
					ssoAccountId: "ssoAccountId",
					ssoRegion:    "ssoRegion",
					ssoRoleName:  "ssoRoleName",
					ssoStartUrl:  "ssoStartUrl",
					ssoSession:   "",
				},
			},
			want:    userHomeDir + "/.aws/sso/cache/89cdeb16c173b8923b9a6bf9bc154479f2726122.json",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCacheFilePath(tt.args.profile)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCacheFilePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getCacheFilePath() got = %v, want %v", got, tt.want)
			}
		})
	}
}
