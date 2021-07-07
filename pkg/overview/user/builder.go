package user

import (
	"bytes"
	"github.com/hazcod/crowdstrike-spotlight-slacker/config"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/falcon"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"html/template"
)

func BuildUserOverviewMessage(logger *logrus.Logger, config *config.Config, slackUser slack.User, falconResult falcon.FalconResult) (string, error) {
	if config.Templates.UserMessage == "" {
		return "", errors.New("no user message template defined")
	}

	messageTemplate, err := template.New("message").Parse(config.Templates.UserMessage)
	if err != nil {
		logrus.WithError(err).Fatal("unable to parse message")
	}

	variables := struct {
		Slack slack.User
		User falcon.FalconResult
	}{
		Slack: slackUser,
		User: falconResult,
	}

	var buffer bytes.Buffer
	if err := messageTemplate.Execute(&buffer, &variables); err != nil {
		logrus.WithError(err).Fatal("could not parse user message")
	}

	logrus.WithField("message", buffer.String()).Debug("built user overview message")

	return buffer.String(), nil
}
