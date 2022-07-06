package config

import (
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

const (
	appEnvPrefix = "CSS"
)

type Config struct {
	Slack struct {
		Token        string   `yaml:"token" env:"SLACK_TOKEN"`
		SecurityUser []string `yaml:"security_user" emv:"SLACK_SECURITY_USER"`

		SkipNoReport  bool `yaml:"skip_no_report" env:"SLACK_SKIP_NO_REPORT"`
		SkipOnHoliday bool `yaml:"skip_on_holiday" env:"SLACK_SKIP_ON_HOLIDAY"`
	} `yaml:"slack"`

	Falcon struct {
		ClientID    string `yaml:"clientid" env:"FALCON_CLIENT_ID"`
		Secret      string `yaml:"secret" env:"FALCON_SECRET"`
		CloudRegion string `yaml:"cloud_region" env:"FALCON_CLOUD_REGION"`

		SkipNoMitigation   bool     `yaml:"skip_no_mitigation" env:"FALCON_SKIP_NO_MITIGATION"`
		SkipSeverities     []string `yaml:"skip_severities" env:"FALCON_SKIP_SEVERITIES"`
		MinCVEBaseScore    int      `yaml:"min_cve_base_score" env:"FALCON_MIN_CVE_BASE_SCORE"`
		SkipCVEs           []string `yaml:"skip_cves" env:"FALCON_SKIP_CVES"`
		MinExprtAISeverity string   `yaml:"min_exprtai_severity" env:"FALCON_MIN_EXPRTAI_SEVERITYs"`
	} `yaml:"falcon"`

	WS1 struct {
		Endpoint string `yaml:"api_url" env:"WS1_API_URL"`
		APIKey   string `yaml:"api_key" env:"WS1_API_KEY"`
		User     string `yaml:"user" env:"WS1_USER"`
		Password string `yaml:"password" env:"WS1_PASSWORD"`

		SkipFilters []struct {
			Policy string `yaml:"policy"`
			User   string `yaml:"user"`
		} `yaml:"skip"`
	} `yaml:"ws1"`

	Email struct {
		Domains   []string `yaml:"domains" env:"DOMAINS"`
		Whitelist []string `yaml:"whitelist" env:"WHITELIST"`
	} `yaml:"email"`

	Templates struct {
		UserMessage             string `yaml:"user_message" env:"USER_MESSAGE"`
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

	if len(c.Email.Domains) == 0 {
		return errors.New("missing email domain(s)")
	}

	if c.Templates.UserMessage == "" {
		return errors.New("missing message")
	}

	return nil
}
