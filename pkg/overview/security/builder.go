package security

import (
	"bytes"
	"github.com/hazcod/crowdstrike-spotlight-slacker/config"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/falcon"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"html/template"
	"time"
)

func BuildSecurityOverviewMessage(logger *logrus.Logger, config config.Config, falconResults map[string]falcon.FalconResult, reportedErrors []error) (string, error) {
	messageTemplate, err := template.New("message").Parse(config.Templates.SecurityOverviewMessage)
	if err != nil {
		return "", errors.Wrap(err, "unable to parse message")
	}

	variables := struct {
		Results map[string]falcon.FalconResult
		Date time.Time
		Errors []error
	}{
		Date: time.Now(),
		Results: falconResults,
		Errors: reportedErrors,
	}

	var buffer bytes.Buffer
	if err := messageTemplate.Execute(&buffer, &variables); err != nil {
		return "", errors.Wrap(err, "could not parse security overview")
	}

	logrus.WithField("message", buffer.String()).Debug("built security overview message")

	return buffer.String(), nil
}
