package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	config2 "github.com/hazcod/crowdstrike-spotlight-slacker/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"log"
	"os"
	"strings"
	"text/template"
)

const (
	tagEmailPrefix = "email/"
	tagFalconPrefix = "FalconGroupingTags/"
)

var (
	falconAPIMaxRecords = int64(400)
)

type DeviceUser struct {
	Email 	string
	Devices []UserDevice
}

type UserDevice struct {
	MachineName string
	Tags 	 	[]string
	Findings 	[]UserDeviceFinding
}

type UserDeviceFinding struct {
	ProductName string
	CveID 		string
	CveSeverity string
	MitigationAvailable bool
	TimestampFound 		string
}

func getUniqueDeviceID(hostInfo models.DomainAPIVulnerabilityHostInfoV2) (string, error) {
	b, err := json.Marshal(&hostInfo)
	if err != nil { return "", err }
	hasher := sha1.New()
	if _, err := hasher.Write(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func findEmailTag(tags []string, emailHost string) (email string, err error) {
	for _, tag := range tags {
		tag = strings.ToLower(tag)
		tag = strings.TrimLeft(tag, strings.ToLower(tagFalconPrefix))

		logrus.WithField("tag", tag).Debug("looking at falcon tag")

		if !strings.HasPrefix(tag, tagEmailPrefix) {
			continue
		}

		if email != "" {
			logrus.
				WithField("tag", tag).WithField("email", email).
				WithField("prefix", tagEmailPrefix).
				Warn("multiple user tags found")
		}

		email = strings.TrimLeft(tag, tagEmailPrefix)
	}

	if email == "" {
		return "", errors.New("email tag not found")
	}

	email = strings.ToLower(email)
	email = strings.Replace(email, fmt.Sprintf("/%s", emailHost), fmt.Sprintf("@%s", emailHost), 1)
	email = strings.ReplaceAll(email, "/", ".")

	if !strings.Contains(email, "@") || !strings.Contains(email, "."){
		return "", errors.New("invalid email address: " + email)
	}

	return email, nil
}

func main() {
	ctx := context.Background()

	configPath := flag.String("config", "", "Path to your config file.")
	logLevelStr:= flag.String("log", "info", "Log level.")
	flag.Parse()

	logLevel, err := logrus.ParseLevel(*logLevelStr)
	if err != nil {
		logrus.WithError(err).Fatal("could not parse log level")
	}
	logrus.SetLevel(logLevel)

	config, err := config2.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("could not load configuration: %s", err)
	}

	if err := config.Validate(); err != nil {
		logrus.WithError(err).Fatal("invalid configuration")
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId: config.Falcon.ClientID,
		ClientSecret: config.Falcon.Secret,
		Cloud: falcon.Cloud(config.Falcon.CloudRegion),
		Context: ctx,
	})
	if err != nil {
		logrus.WithError(err).Fatal("could not init falcon client")
	}

	queryResult, err := client.SpotlightVulnerabilities.QueryVulnerabilities(
		&spotlight_vulnerabilities.QueryVulnerabilitiesParams{
			Context: context.Background(),
			Filter: "status:'open',remediation.ids:'*'",
			Limit: &falconAPIMaxRecords,
		},
	)
	if err != nil {
		logrus.
			WithField("error", fmt.Sprintf("%+v", err)).
			Fatal("could not query vulnerabilities")
	}

	if queryResult == nil {
		logrus.Fatal("result is nil")
	}

	var vulnIDs []string
	vulnIDs = append(vulnIDs, queryResult.GetPayload().Resources...)

	if len(vulnIDs) == 0 {
		logrus.Println("no vulnerabilities found")
		os.Exit(0)
	}

	logrus.WithField("vulns", len(vulnIDs)).Info("found vulnerabilities")

	getResult, err := client.SpotlightVulnerabilities.GetVulnerabilities(
		&spotlight_vulnerabilities.GetVulnerabilitiesParams{
			Ids:        vulnIDs,
			Context:    context.Background(),
		},
	)
	if err != nil {
		logrus.
			WithField("error", err.Error()).
			Fatal("could not query vulnerabilities")
	}

	if len(getResult.GetPayload().Resources) != len(vulnIDs) {
		logrus.Warn("result payload not as large as vuln list")
	}

	var hostTags []string
	devices := map[string]UserDevice{}

	for _, vuln := range getResult.GetPayload().Resources {
		if len(vuln.Remediation.Ids) == 0 {
			//logrus.WithField("app", *vuln.App.ProductNameVersion).Warn("skipping vulnerability without remediation")
			continue
		}

		uniqueDeviceID, err := getUniqueDeviceID(*vuln.HostInfo)
		if err != nil {
			logrus.WithError(err).Error("could not calculate unique device id")
			continue
		}

		deviceFinding := UserDeviceFinding{
			ProductName:         *vuln.App.ProductNameVersion,
			CveID:               *vuln.Cve.ID,
			CveSeverity:         *vuln.Cve.Severity,
			MitigationAvailable: true,
			TimestampFound:      *vuln.CreatedTimestamp,
		}

		if _, ok := devices[uniqueDeviceID]; !ok {
			devices[uniqueDeviceID] = UserDevice{
				MachineName: fmt.Sprintf(
					"%s %s",
					*vuln.HostInfo.OsVersion,
					*vuln.HostInfo.Hostname,
				),
				Tags:        vuln.HostInfo.Tags,
				Findings:    []UserDeviceFinding{},
			}
		}

		device := devices[uniqueDeviceID]

		found := false
		for _, finding := range device.Findings {
			if strings.EqualFold(finding.ProductName, deviceFinding.ProductName) {
				found = true
				break
			}
		}

		if !found {
			device.Findings = append(device.Findings, deviceFinding)
			devices[uniqueDeviceID] = device
		}

		hostTags = append(hostTags, device.Tags...)
	}

	if len(devices) == 0 {
		logrus.Println("no vulnerabilities found with mitigations")
		os.Exit(0)
	}

	if len(hostTags) == 0 {
		logrus.Fatal("no tags found on hosts")
	}

	logrus.WithField("devices", len(devices)).Info("found vulnerable devices")

	users := map[string]DeviceUser{}

	for _, device := range devices {
		userEmail, err := findEmailTag(device.Tags, config.Email.Domain)
		if err != nil {
			logrus.
				WithError(err).
				WithField("tags", device.Tags).
				WithField("prefix", tagEmailPrefix).
				WithField("device", device.MachineName).
				Warn("could extract user email tag, using fallback Slack user")

			userEmail = config.Slack.FallbackUser
		}

		user, ok := users[userEmail]
		if !ok {
			users[userEmail] = DeviceUser{
				Email:   userEmail,
				Devices: []UserDevice{},
			}
		}

		user.Devices = append(user.Devices, device)
		user.Email = userEmail
		users[userEmail] = user
	}

	logrus.Debugf("%+v", users)

	slackClient := slack.New(config.Slack.Token)

	logrus.Info("fetching slack users")
	slackUsers, err := slackClient.GetUsers()
	if err != nil {
		logrus.WithError(err).Fatal("could not fetch slack users")
	}

	for _, user := range users {
		logrus.WithField("user", user.Email).Debug("handling user at risk")

		var theSlackUser slack.User
		for _, slackUser := range slackUsers {
			if ! strings.EqualFold(user.Email, slackUser.Profile.Email) {
				continue
			}
			theSlackUser = slackUser
		}

		if theSlackUser.Name == "" {
			logrus.WithField("user", user.Email).Error("slack user not found")
			continue
		}

		if theSlackUser.IsBot {
			logrus.WithField("user", user.Email).Error("user is a Slack bot")
			continue
		}

		messageTemplate, err := template.New("message").Parse(config.Message)
		if err != nil {
			logrus.WithError(err).Fatal("unable to parse message")
		}

		variables := struct {
			Slack  slack.User
			User   DeviceUser
		}{
			Slack: theSlackUser,
			User: user,
		}

		var buffer bytes.Buffer
		if err := messageTemplate.Execute(&buffer, &variables); err != nil {
			logrus.WithError(err).Fatal("could not parse message")
		}

		if _, _, _, err := slackClient.SendMessage(
			theSlackUser.ID,
			slack.MsgOptionText(buffer.String(), false),
			slack.MsgOptionAsUser(true),
		); err != nil {
			logrus.WithError(err).
				WithField("user", theSlackUser.Profile.Email).
				Error("could not send slack message")
			continue
		}

		logrus.
			WithField("user", user.Email).WithField("devices", len(user.Devices)).
			Info("sent reminder on Slack")
	}
}
