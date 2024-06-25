package aws_sdk_go_v2_sso_login

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
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

// TODO mock cfg
func Test_getAwsCredsFromCache(t *testing.T) {
	type args struct {
		ctx           context.Context
		cfg           *aws.Config
		profile       *configProfile
		cacheFilePath string
	}
	tests := []struct {
		name    string
		args    args
		want    *aws.Credentials
		want1   *aws.CredentialsCache
		wantErr bool
	}{
		{
			name: "check error type",
			args: args{
				ctx:           nil,
				cfg:           nil,
				profile:       nil,
				cacheFilePath: "",
			},
			want:    nil,
			want1:   nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getAwsCredsFromCache(tt.args.ctx, tt.args.cfg, tt.args.profile, tt.args.cacheFilePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("getAwsCredsFromCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && tt.wantErr {
				if !errors.Is(err, CredCacheError) {
					t.Errorf("getAwsCredsFromCache() error = %v, wantErr %v", err, CredCacheError)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getAwsCredsFromCache() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("getAwsCredsFromCache() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
