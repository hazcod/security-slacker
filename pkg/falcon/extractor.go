package falcon

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hazcod/crowdstrike-spotlight-slacker/config"
	"github.com/sirupsen/logrus"
)

const (
	tagEmailPrefix  = "email/"
	tagFalconPrefix = "FalconGroupingTags/"
)

type FalconResult struct {
	Email   string
	Devices []UserDevice
}

type UserDevice struct {
	MachineName string
	Tags        []string
	Findings    []UserDeviceFinding
}

type UserDeviceFinding struct {
	ProductName         string
	CveID               string
	CveSeverity         string
	MitigationAvailable bool
	TimestampFound      string
}

func getUniqueDeviceID(hostInfo models.DomainAPIVulnerabilityHostInfoV2) (string, error) {
	b, err := json.Marshal(&hostInfo)
	if err != nil {
		return "", err
	}
	hasher := sha1.New()
	if _, err := hasher.Write(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func findEmailTag(tags []string, emailDomains []string) (email string, err error) {
	theTag := ""

	for _, tag := range tags {
		tag = strings.ToLower(tag)
		tag = strings.TrimLeft(tag, strings.ToLower(tagFalconPrefix))

		logrus.WithField("tag", tag).Trace("looking at falcon tag")

		if !strings.HasPrefix(tag, tagEmailPrefix) {
			continue
		}

		if theTag != "" {
			logrus.
				WithField("tag", tag).WithField("email", theTag).
				WithField("prefix", tagEmailPrefix).
				Warn("multiple user tags found")
		}

		theTag = strings.TrimLeft(tag, tagEmailPrefix)
	}

	if theTag == "" {
		return "", errors.New("email tag not found")
	}

	theTag = strings.ToLower(theTag)

	for _, domain := range emailDomains {
		if ! strings.Contains(theTag ,strings.ToLower(domain)) {
			continue
		}

		email = theTag
		email = strings.Replace(email, fmt.Sprintf("/%s", domain), fmt.Sprintf("@%s", domain), 1)
		email = strings.ReplaceAll(email, "/", ".")

		break
	}

	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return "", errors.New("invalid email address: " + email)
	}

	logrus.WithField("tag", theTag).WithField("email", email).Debug("converted tag to email")

	return email, nil
}

func GetMessages(config *config.Config, ctx context.Context) (results map[string]FalconResult, err error) {
	falconAPIMaxRecords := int64(400)

	results = map[string]FalconResult{}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     config.Falcon.ClientID,
		ClientSecret: config.Falcon.Secret,
		Cloud:        falcon.Cloud(config.Falcon.CloudRegion),
		Context:      ctx,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize Falcon client")
	}

	queryResult, err := client.SpotlightVulnerabilities.QueryVulnerabilities(
		&spotlight_vulnerabilities.QueryVulnerabilitiesParams{
			Context: ctx,
			Filter:  "status:'open',remediation.ids:'*'",
			Limit:   &falconAPIMaxRecords,
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not query vulnerabilities")
	}

	if queryResult == nil {
		return nil, errors.New("QueryVulnerabilities result was nil")
	}

	var vulnIDs []string
	vulnIDs = append(vulnIDs, queryResult.GetPayload().Resources...)

	if len(vulnIDs) == 0 {
		return results, nil
	}

	logrus.WithField("vulns", len(vulnIDs)).Info("found vulnerabilities")

	getResult, err := client.SpotlightVulnerabilities.GetVulnerabilities(
		&spotlight_vulnerabilities.GetVulnerabilitiesParams{
			Ids:     vulnIDs,
			Context: context.Background(),
		},
	)
	if err != nil || getResult == nil {
		return nil, errors.Wrap(err, "could not get Falcon vulnerabilities")
	}

	if len(getResult.GetPayload().Resources) != len(vulnIDs) {
		logrus.Warn("result payload not as large as vuln list")
	}

	var hostTags []string
	devices := map[string]UserDevice{}

	for _, vuln := range getResult.GetPayload().Resources {

		if len(vuln.Remediation.Ids) == 0 && config.Falcon.SkipNoMitigation {
			logrus.WithField("app", *vuln.App.ProductNameVersion).Debug("skipping vulnerability without remediation")

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
			MitigationAvailable: len(vuln.Remediation.Ids) > 0,
			TimestampFound:      *vuln.CreatedTimestamp,
		}

		logrus.Warnf("%+v", vuln.HostInfo.Tags)

		if !deviceFinding.MitigationAvailable {
			logrus.WithField("cve",*vuln.Cve.ID).WithField("severity", *vuln.Cve.Severity).
				WithField("product", *vuln.App.ProductNameVersion).
				Warn("skipping finding without mitigation(s)")
			continue
		}

		if _, ok := devices[uniqueDeviceID]; !ok {
			devices[uniqueDeviceID] = UserDevice{
				MachineName: fmt.Sprintf(
					"%s %s",
					*vuln.HostInfo.OsVersion,
					*vuln.HostInfo.Hostname,
				),
				Tags:     vuln.HostInfo.Tags,
				Findings: []UserDeviceFinding{},
			}
		}

		device := devices[uniqueDeviceID]

		findingExists := false

		for _, finding := range device.Findings {
			if strings.EqualFold(finding.ProductName, deviceFinding.ProductName) {
				findingExists = true
				break
			}
		}

		if !findingExists {
			device.Findings = append(device.Findings, deviceFinding)
		}

		device.Tags = append(device.Tags, vuln.HostInfo.Tags...)

		devices[uniqueDeviceID] = device

		hostTags = append(hostTags, device.Tags...)
	}

	if len(devices) == 0 {
		return results, nil
	}

	if len(hostTags) == 0 {
		return nil, errors.New("no tags found on decices")
	}

	logrus.WithField("devices", len(devices)).Info("found vulnerable devices")

	for _, device := range devices {
		userEmail, err := findEmailTag(device.Tags, config.Email.Domains)
		if err != nil {
			logrus.
				WithError(err).
				WithField("tags", device.Tags).
				WithField("prefix", tagEmailPrefix).
				WithField("device", device.MachineName).
				Warn("could extract user email tag, using fallback Slack user")

			userEmail = config.Slack.SecurityUser
		}

		user, ok := results[userEmail]
		if !ok {
			results[userEmail] = FalconResult{
				Email:   userEmail,
				Devices: []UserDevice{},
			}
		}

		user.Devices = append(user.Devices, device)
		user.Email = userEmail
		results[userEmail] = user
	}

	logrus.Debugf("%+v", results)

	return results, nil
}
