package main

import (
	"context"
	"flag"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/overview/security"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/overview/user"
	"github.com/pkg/errors"
	"os"
	"strings"

	config2 "github.com/hazcod/crowdstrike-spotlight-slacker/config"
	"github.com/hazcod/crowdstrike-spotlight-slacker/pkg/falcon"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
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

	falconMessages, err := falcon.GetMessages(config, ctx)
	if err != nil {
		logrus.WithError(err).Fatal("could not get falcon messages")
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

	for userEmail, falconResult := range falconMessages {
		logrus.WithField("user", userEmail).Debug("handling user at risk")

		var theSlackUser slack.User
		for _, slackUser := range slackUsers {
			if !strings.EqualFold(userEmail, slackUser.Profile.Email) {
				continue
			}
			theSlackUser = slackUser
		}

		if theSlackUser.Name == "" {
			logrus.WithField("user", userEmail).Error("slack user not found")
			errorsToReport = append(errorsToReport, errors.New("User not found on Slack: " + userEmail))
			continue
		}

		if theSlackUser.IsBot {
			logrus.WithField("user", userEmail).Error("user is a Slack bot")
			continue
		}

		slackMessage, err := user.BuildUserOverviewMessage(logrus.StandardLogger(), config, theSlackUser, falconMessages[falconResult.Email])
		if err != nil {
			logrus.WithError(err).WithField("user", theSlackUser.Profile.Email).Error("could not generate user message")
			continue
		}

		if !*dryMode {
			if _, _, _, err := slackClient.SendMessage(
				theSlackUser.ID,
				slack.MsgOptionText(slackMessage, false),
				slack.MsgOptionAsUser(true),
			); err != nil {
				logrus.WithError(err).
					WithField("user", theSlackUser.Profile.Email).
					Error("could not send slack message")
				continue
			}
		}

		logrus.
			WithField("user", falconResult.Email).WithField("devices", len(falconResult.Devices)).
			Info("sent reminder on Slack")
	}

	/*
	if len(falconMessages) == 0 {
		logrus.Info("nothing to report, exiting")
		os.Exit(0)
	}
	*/

	if config.Templates.SecurityOverviewMessage == "" {
		logrus.Info("not sending a security overview")
		os.Exit(0)
	}

	overviewText, err := security.BuildSecurityOverviewMessage(logrus.StandardLogger(), *config, falconMessages, errorsToReport)
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
