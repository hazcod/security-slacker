package config

import (
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

const (
	appEnvPrefix = "CSS"
)

type Config struct {
	Slack struct {
		Token        string `yaml:"token" env:"SLACK_TOKEN"`
		SecurityUser string `yaml:"security_user" emv:"SLACK_SECURITY_USER"`
	} `yaml:"slack"`

	Falcon struct {
		ClientID    string `yaml:"clientid" env:"FALCON_CLIENT_ID"`
		Secret      string `yaml:"secret" env:"FALCON_SECRET"`
		CloudRegion string `yaml:"cloud_region" env:"FALCON_CLOUD_REGION"`

		SkipNoMitigation bool `yaml:"skip_no_mitigation" env:"FALCON_SKIP_NO_MITIGATION"`
	} `yaml:"falcon"`

	Email struct {
		Domain string `yaml:"domain" env:"DOMAIN"`
	} `yaml:"email"`

	Templates struct {
		UserMessage string `yaml:"user_message" env:"USER_MESSAGE"`
		SecurityOverviewMessage string `yaml:"security_overview_message" env:"SECURITY_OVERVIEW_MESSAGE"`
	} `yaml:"templates"`
}

func LoadConfig(logger *logrus.Logger, path string) (*Config, error) {
	var config Config

	if path != "" {
		configBytes, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, errors.Wrap(err, "could not load configuration file")
		}

		if err := yaml.Unmarshal(configBytes, &config); err != nil {
			return nil, errors.Wrap(err, "could not parse configuration file")
		}

		logger.Info("loaded configuration from " + path)
	}

	if err := envconfig.Process(appEnvPrefix, &config); err != nil {
		return nil, errors.Wrap(err, "could not load environment variables")
	}

	return &config, nil
}

func (c *Config) Validate() error {
	if c.Slack.Token == "" {
		return errors.New("missing slack token")
	}

	if c.Falcon.ClientID == "" {
		return errors.New("missing falcon clientid")
	}

	if c.Falcon.Secret == "" {
		return errors.New("missing falcon secret")
	}

	if c.Falcon.CloudRegion == "" {
		return errors.New("missing falcon cloud region")
	}

	if c.Email.Domain == "" {
		return errors.New("missing email domain")
	}

	if c.Templates.UserMessage == "" {
		return errors.New("missing message")
	}

	return nil
}
