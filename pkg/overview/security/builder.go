package security

import (
	"bytes"
	"github.com/hazcod/crowdstrike-spotlight-slacker/config"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/falcon"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/ws1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"html/template"
	"time"
)

func BuildSecurityOverviewMessage(logger *logrus.Logger, config config.Config, falconResults map[string]falcon.FalconResult, ws1Results map[string]ws1.WS1Result, reportedErrors []error) (string, error) {
	messageTemplate, err := template.New("message").Parse(config.Templates.SecurityOverviewMessage)
	if err != nil {
		return "", errors.Wrap(err, "unable to parse message")
	}

	var allFalcon []falcon.FalconResult
	for _, f := range falconResults {
		allFalcon = append(allFalcon, f)
	}

	var allWS1 []ws1.WS1Result
	for _, w := range ws1Results {
		hasIssues := false
		for _, device := range w.Devices {
			if len(device.Findings) > 0 {
				hasIssues = true
				break
			}
		}

		if hasIssues {
			allWS1 = append(allWS1, w)
		}
	}

	logrus.Debugf("findings: falcon: %d ws1: %d", len(allFalcon), len(allWS1))

	variables := struct {
		Falcon        []falcon.FalconResult
		WS1           []ws1.WS1Result
		Date          time.Time
		Errors        []error
		MissingSensor []ws1.UserDevice
	}{
		Date:   time.Now(),
		Falcon: allFalcon,
		WS1:    allWS1,
		Errors: reportedErrors,
		//MissingSensor: devicesWithoutFalcon,
	}

	var buffer bytes.Buffer
	if err := messageTemplate.Execute(&buffer, &variables); err != nil {
		return "", errors.Wrap(err, "could not parse security overview")
	}

	logrus.WithField("message", buffer.String()).Debug("built security overview message")

	return buffer.String(), nil
}
