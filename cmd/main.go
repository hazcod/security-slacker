package main

import (
	"context"
	"flag"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/overview/security"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/overview/user"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/ws1"
	"os"
	"strings"

	config2 "github.com/hazcod/crowdstrike-spotlight-slacker/config"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/falcon"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

const (
	slackStatusHoliday = "vacationing"
)

func main() {
	ctx := context.Background()

	configPath := flag.String("config", "", "Path to your config file.")
	logLevelStr := flag.String("log", "info", "Log level.")
	dryMode := flag.Bool("dry", false, "whether we run in dry-run mode and send nothing to the users.")
	flag.Parse()

	logLevel, err := logrus.ParseLevel(*logLevelStr)
	if err != nil {
		logrus.WithError(err).Fatal("could not parse log level")
	}
	logrus.SetLevel(logLevel)

	if *dryMode {
		logrus.Warn("running in dry mode, nothing will be sent to the users")
	}

	config, err := config2.LoadConfig(logrus.StandardLogger(), *configPath)
	if err != nil {
		logrus.Fatalf("could not load configuration: %s", err)
	}

	if err := config.Validate(); err != nil {
		logrus.WithError(err).Fatal("invalid configuration")
	}

	// ---

	falconMessages, err := falcon.GetMessages(config, ctx)
	if err != nil {
		logrus.WithError(err).Fatal("could not get falcon messages")
	}

	ws1Messages, err := ws1.GetMessages(config, ctx)
	if err != nil {
		logrus.WithError(err).Fatal("could not get WS1 messages")
	}

	// ---

	slackClient := slack.New(config.Slack.Token)

	logrus.Debug("fetching slack users")
	slackUsers, err := slackClient.GetUsers()
	if err != nil {
		logrus.WithError(err).Fatal("could not fetch slack users")
	}

	securityUserID := ""
	for _, slackUser := range slackUsers {
		if strings.EqualFold(slackUser.Profile.Email, config.Slack.SecurityUser) {
			securityUserID = slackUser.ID
			break
		}
	}

	if securityUserID == "" {
		logrus.WithField("fallback_user", config.Slack.SecurityUser).
			Fatal("could not find fallback user on Slack")
	}

	logrus.WithField("users", len(slackUsers)).Info("found Slack users")

	var errorsToReport []error

	for _, slackUser := range slackUsers {
		userEmail := strings.ToLower(slackUser.Profile.Email)

		if slackUser.IsBot {
			continue
		}

		userFalconMsg := falconMessages[userEmail]

		userWS1Msg := ws1Messages[userEmail]

		if len(userFalconMsg.Devices) == 0 && len(userWS1Msg.Devices) == 0 {
			continue
		}

		if config.Slack.SkipOnHoliday && strings.EqualFold(slackUser.Profile.StatusText, slackStatusHoliday) {
			logrus.WithField("slack_name", slackUser.Name).Warn("skipping user since he/she is on holiday")
			continue
		}

		logrus.WithField("falcon", userFalconMsg).WithField("ws1", userWS1Msg).WithField("email", userEmail).
			Debug("found messages")

		slackMessage, err := user.BuildUserOverviewMessage(logrus.StandardLogger(), config, slackUser, falconMessages[userEmail], ws1Messages[userEmail])
		if err != nil {
			logrus.WithError(err).WithField("user", slackUser.Profile.Email).Error("could not generate user message")
			continue
		}

		if slackMessage == "" {
			continue
		}

		if !*dryMode {
			if _, _, _, err := slackClient.SendMessage(
				slackUser.ID,
				slack.MsgOptionText(slackMessage, false),
				slack.MsgOptionAsUser(true),
			); err != nil {
				logrus.WithError(err).
					WithField("user", slackUser.Profile.Email).
					Error("could not send slack message")
				continue
			}
		}

		logrus.WithField("user", userEmail).Info("sent notice on Slack")
	}

	if config.Templates.SecurityOverviewMessage == "" {
		logrus.Warn("not sending a security overview since template is empty")
		os.Exit(0)
	}

	if config.Slack.SkipNoReport {
		if len(falconMessages) == 0 && len(ws1Messages) == 0 {
			logrus.Info("nothing to report, exiting")
			os.Exit(0)
		}
	}

	overviewText, err := security.BuildSecurityOverviewMessage(logrus.StandardLogger(), *config, falconMessages, ws1Messages, errorsToReport)
	if err != nil {
		logrus.WithError(err).Fatal("could not generate security overview")
	}

	logrus.WithField("email", config.Slack.SecurityUser).
		Debug("sending security report to security user")

	if _, _, _, err := slackClient.SendMessage(
		securityUserID, slack.MsgOptionText(overviewText, false), slack.MsgOptionAsUser(true),
	); err != nil {
		logrus.WithField("email", config.Slack.SecurityUser).WithError(err).
			Fatal("could not send security overview to security user")
	}

	logrus.WithField("email", config.Slack.SecurityUser).Info("sent security overview to security user")
}
