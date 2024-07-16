package aws_sdk_go_v2_sso_login

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/google/uuid"
	"io/fs"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func Test_getConfigProfile(t *testing.T) {
	type args struct {
		profileName    string
		configFilePath string
	}

	fakeFileLocation := uuid.New().String()
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
			name: "missing config file",
			args: args{
				profileName:    "",
				configFilePath: fakeFileLocation,
			},
			want:           nil,
			wantErrorValue: NewLoadingConfigFileError(fakeFileLocation, &fs.PathError{Op: "open", Path: fakeFileLocation, Err: syscall.Errno(2)}),
			ErrorAsType:    &LoadingConfigFileError{},
		},
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
			name: "missing_sso_account_id",
			args: args{
				profileName:    "missing_sso_account_id",
				configFilePath: missingArgsConfLocation,
			},
			want:           nil,
			wantErrorValue: NewProfileValidationError("missing_sso_account_id", missingArgsConfLocation, "sso_account_id", "", "<non empty>"),
			ErrorAsType:    &ProfileValidationError{},
		},
		{
			name: "missing_sso_region",
			args: args{
				profileName:    "missing_sso_region",
				configFilePath: missingArgsConfLocation,
			},
			want:           nil,
			wantErrorValue: NewProfileValidationError("missing_sso_region", missingArgsConfLocation, "sso_region", "", "<non empty>"),
			ErrorAsType:    &ProfileValidationError{},
		},
		{
			name: "missing_sso_role_name",
			args: args{
				profileName:    "missing_sso_role_name",
				configFilePath: missingArgsConfLocation,
			},
			want:           nil,
			wantErrorValue: NewProfileValidationError("missing_sso_role_name", missingArgsConfLocation, "sso_role_name", "", "<non empty>"),
			ErrorAsType:    &ProfileValidationError{},
		},
		{
			name: "missing_sso_start_url",
			args: args{
				profileName:    "missing_sso_start_url",
				configFilePath: missingArgsConfLocation,
			},
			want:           nil,
			wantErrorValue: NewProfileValidationError("missing_sso_start_url", missingArgsConfLocation, "sso_start_url", "", "<non empty>"),
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
				ssoStartUrl:  "https://my-sso-portal.awsapps.com/start",
			},
			wantErrorValue: nil,
			ErrorAsType:    nil,
		},
		{
			name: "missing output",
			args: args{
				profileName:    "missing_output",
				configFilePath: missingArgsConfLocation,
			},
			want: &configProfile{
				name:         "missing_output",
				output:       "json",
				region:       "us-west-2",
				ssoAccountId: "sso_account_id",
				ssoRegion:    "sso_region",
				ssoRoleName:  "sso_role_name",
				ssoStartUrl:  "https://my-sso-portal.awsapps.com/start",
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
				ssoStartUrl:  "https://my-sso-portal.awsapps.com/start",
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

func Test_writeCacheFile(t *testing.T) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		cacheFileData *cacheFileData
		cacheFilePath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "",
			args: args{
				cacheFileData: &cacheFileData{
					StartUrl:              "StartUrl",
					Region:                "Region",
					AccessToken:           "AccessToken",
					ExpiresAt:             time.Time{},
					ClientId:              "ClientId",
					ClientSecret:          "ClientSecret",
					RegistrationExpiresAt: time.Time{},
				},
				cacheFilePath: "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDirPath := userHomeDir + "/" + uuid.New().String()
			cacheFilePath := cacheDirPath + "/fake.json"
			defer os.RemoveAll(cacheDirPath)

			tt.args.cacheFilePath = cacheFilePath

			if err := writeCacheFile(tt.args.cacheFileData, tt.args.cacheFilePath); (err != nil) != tt.wantErr {
				t.Errorf("writeCacheFile() error = %v, wantErr %v", err, tt.wantErr)
			}

			plan, _ := os.ReadFile(cacheFilePath)
			var data cacheFileData
			err := json.Unmarshal(plan, &data)

			if err != nil {
				t.Errorf("writeCacheFile() failed to unmarshal chache json")
			}

			if data != *tt.args.cacheFileData {
				t.Errorf("writeCacheFile() got = %v, want %v", data, tt.args.cacheFileData)
			}
		})
	}
}

func Test_getAwsCredsFromCache(t *testing.T) {
	testConfLocation := "testdata/aws_configs"
	profilesLocation := testConfLocation + "/profiles.ini"

	type args struct {
		ctx           context.Context
		cfg           *aws.Config
		profile       *configProfile
		cacheFilePath string
	}
	tests := []struct {
		name           string
		profileName    string
		args           args
		want           *aws.Credentials
		want1          *aws.CredentialsCache
		wantErrorValue error
	}{
		{
			name:        "",
			profileName: "complete",
			args: args{
				ctx: context.Background(),
				cfg: nil,
				profile: &configProfile{
					name:         "",
					output:       "",
					region:       "",
					ssoAccountId: "",
					ssoRegion:    "",
					ssoRoleName:  "",
					ssoStartUrl:  "",
					ssoSession:   "",
				},
				cacheFilePath: "",
			},
			want:           nil,
			want1:          nil,
			wantErrorValue: CredCacheError{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sharedConfigFileLocations []string
			sharedConfigFileLocations = append(sharedConfigFileLocations, profilesLocation)
			sharedConfigProfile := config.WithSharedConfigProfile(tt.profileName)
			sharedConfigFile := config.WithSharedConfigFiles(sharedConfigFileLocations)

			cfg, err := config.LoadDefaultConfig(context.Background(), sharedConfigProfile, sharedConfigFile)
			if err != nil {
				panic(err)
			}
			tt.args.cfg = &cfg

			got, got1, err := getAwsCredsFromCache(tt.args.ctx, tt.args.cfg, tt.args.profile, tt.args.cacheFilePath)
			if (err != nil) && tt.wantErrorValue == nil {
				t.Errorf("getAwsCredsFromCache() error = %v, wantErr %v", err, tt.wantErrorValue)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getAwsCredsFromCache() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("getAwsCredsFromCache() got1 = %v, want %v", got1, tt.want1)
			}
			if (err != nil) && tt.wantErrorValue != nil {
				if err.Error() != tt.wantErrorValue.Error() {
					t.Errorf("getConfigProfile() error = %v, wantErr %v", err, tt.wantErrorValue)
				}
			}
		})
	}
}

func Test_ssoLoginFlow(t *testing.T) {
	testConfLocation := "testdata/aws_configs"
	profilesLocation := testConfLocation + "/profiles.ini"

	type args struct {
		ctx          context.Context
		cfg          *aws.Config
		profile      *configProfile
		headed       bool
		loginTimeout time.Duration
	}
	tests := []struct {
		name    string
		args    args
		want    *cacheFileData
		wantErr bool
	}{
		{
			name: "",
			args: args{
				ctx: context.Background(),
				profile: &configProfile{
					name:         "",
					output:       "",
					region:       "",
					ssoAccountId: "",
					ssoRegion:    "",
					ssoRoleName:  "",
					ssoStartUrl:  "",
					ssoSession:   "",
				},
				headed:       false,
				loginTimeout: 0,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sharedConfigFileLocations []string
			sharedConfigFileLocations = append(sharedConfigFileLocations, profilesLocation)
			sharedConfigProfile := config.WithSharedConfigProfile("complete")
			sharedConfigFile := config.WithSharedConfigFiles(sharedConfigFileLocations)

			cfg, err := config.LoadDefaultConfig(context.Background(), sharedConfigProfile, sharedConfigFile)
			if err != nil {
				panic(err)
			}
			tt.args.cfg = &cfg

			got, err := ssoLoginFlow(tt.args.ctx, tt.args.cfg, tt.args.profile, tt.args.headed, tt.args.loginTimeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("ssoLoginFlow() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ssoLoginFlow() got = %v, want %v", got, tt.want)
			}
		})
	}
}
