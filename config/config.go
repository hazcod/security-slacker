package config

import (
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

const (
	appEnvPrefix = "CSS"
)

type Config struct {
	Slack struct {
		Token string `yaml:"token" env:"SLACK_TOKEN"`
	} `yaml:"slack"`

	Falcon struct {
		ClientID    string `yaml:"clientid" env:"FALCON_CLIENT_ID"`
		Secret      string `yaml:"secret" env:"FALCON_SECRET"`
		CloudRegion string `yaml:"cloud_region" env:"FALCON_CLOUD_REGION"`
	} `yaml:"falcon"`

	EmailDomain string `yaml:"email_domain" env:"EMAIL_DOMAIN"`

	Message string `yaml:"message" env:"MESSAGE"`
}

func LoadConfig(path string) (*Config, error) {
	var config Config

	if path != "" {
		configBytes, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, errors.Wrap(err, "could not load configuration file")
		}

		if err := yaml.Unmarshal(configBytes, &config); err != nil {
			return nil, errors.Wrap(err, "could not parse configuration file")
		}

		log.Println("loaded configuration from " + path)
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

	if c.EmailDomain == "" {
		return errors.New("missing email domain")
	}

	if c.Message == "" {
		return errors.New("missing message")
	}

	return nil
}
