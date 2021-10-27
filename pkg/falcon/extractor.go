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
	TimestampFound      string
	Mitigations		    []string
}

func getUniqueDeviceID(hostInfo models.DomainAPIVulnerabilityHostFacetV2) (string, error) {
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
	for _, tag := range tags {
		tag = strings.ToLower(tag)
		tag = strings.TrimPrefix(tag, strings.ToLower(tagFalconPrefix))

		logrus.WithField("tag", tag).Trace("looking at falcon tag")

		if !strings.HasPrefix(tag, tagEmailPrefix) {
			continue
		}

		email = strings.TrimPrefix(tag, tagEmailPrefix)
		break
	}

	if email == "" {
		return "", errors.New("email tag not found")
	}

	domainFound := false
	for _, domain := range emailDomains {
		encodedDomain := strings.ToLower(strings.ReplaceAll(domain, ".", "/"))

		if ! strings.HasSuffix(email, encodedDomain) {
			continue
		}

		email = strings.Replace(email, fmt.Sprintf("/%s", encodedDomain), fmt.Sprintf("@%s", domain), 1)
		email = strings.ReplaceAll(email, "/", ".")

		domainFound = true
		break
	}

	if !domainFound {
		return "", errors.New("domain not recognized")
	}

	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return "", errors.New("invalid email address: " + email)
	}

	logrus.WithField("email", email).Debug("converted tag to email")

	return email, nil
}

func appendUnique(main, adder []string) []string {
	for i := range adder {
		found := false

		for j := range main {
			if strings.EqualFold(adder[i], main[j]) {
				found = true
				break
			}
		}

		if found { continue }

		main = append(main, adder[i])
	}

	return main
}

func getSeverityScore(severity string) (int, error) {
	switch strings.TrimSpace(strings.ToLower(severity)) {
	case "":
		return 0, nil
	case "low":
		return 0, nil
	case "medium":
		return 1, nil
	case "high":
		return 2, nil
	case "critical":
		return 3, nil
	}

	return -1, errors.New("unknown severity: " + severity)
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

	queryResult, err := client.SpotlightVulnerabilities.CombinedQueryVulnerabilities(
		&spotlight_vulnerabilities.CombinedQueryVulnerabilitiesParams{
			Context: ctx,
			Filter:  "status:'open'",
			Limit:   &falconAPIMaxRecords,
			Facet: []string{"host_info", "cve", "remediation"},
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not query vulnerabilities")
	}

	if queryResult == nil {
		return nil, errors.New("QueryVulnerabilities result was nil")
	}

	var hostTags []string
	devices := map[string]UserDevice{}

	minExpertAIScore := 0
	if newScore, err := getSeverityScore(config.Falcon.MinExprtAISeverity); err != nil {
		return nil, errors.Wrap(err, "unknown minimum exprtai severity specified")
	} else { minExpertAIScore = newScore }

	for _, vuln := range queryResult.GetPayload().Resources {

		if vuln.Apps == nil {
			continue
		}

		for _, vulnApp := range vuln.Apps {

			if (vulnApp.Remediation == nil || len(vulnApp.Remediation.Ids) == 0) && config.Falcon.SkipNoMitigation {
				logrus.WithField("rem", fmt.Sprintf("%+v", vulnApp.Remediation)).Debug("rem")

				logrus.WithField("app", vulnApp.ProductNameVersion).
					Debug("skipping vulnerability without remediation")

				continue
			}

			if *vuln.Cve.ID != "" && len(config.Falcon.SkipCVEs) > 0 {
				vulnIgnore := false

				for _, cve := range config.Falcon.SkipCVEs {
					if strings.EqualFold(cve, *vuln.Cve.ID) {
						vulnIgnore = true
						break
					}
				}

				if vulnIgnore {
					logrus.WithField("cve", *vuln.Cve.ID).
						WithField("host", *vuln.HostInfo.Hostname).
						Warn("skipping CVE")
					continue
				}
			}

			uniqueDeviceID, err := getUniqueDeviceID(*vuln.HostInfo)
			if err != nil {
				logrus.WithError(err).Error("could not calculate unique device id")

				continue
			}

			if config.Falcon.MinCVEBaseScore > 0 {
				if int(vuln.Cve.BaseScore) < config.Falcon.MinCVEBaseScore {
					logrus.WithField("cve_score", vuln.Cve.BaseScore).Debug("skipping vulnerability")
					continue
				}
			}

			if config.Falcon.MinExprtAISeverity != "" {
				vulnExpertAISevScore, err := getSeverityScore(config.Falcon.MinExprtAISeverity)
				if err != nil {
					logrus.WithField("exprtai_score", vuln.Cve.ExprtRating).WithError(err).
						Error("unknown exprtai score")
				} else {
					if vulnExpertAISevScore < minExpertAIScore {
						logrus.WithField("min_exprtai_severity", config.Falcon.MinExprtAISeverity).
							WithField("exprtai_severity", vuln.Cve.ExprtRating).Debug("skipping vulnerability")
						continue
					}
				}
			}

			if len(config.Falcon.SkipSeverities) > 0 {
				vulnSev := strings.ToLower(vuln.Cve.Severity)
				skip := false

				for _, sev := range config.Falcon.SkipSeverities {
					if strings.EqualFold(sev, vulnSev) {
						logrus.WithField("host", *vuln.HostInfo.Hostname).WithField("cve_score", vuln.Cve.BaseScore).
							WithField("severity", vuln.Cve.Severity).WithField("cve", *vuln.Cve.ID).
							Debug("skipping vulnerability")
						skip = true
						break
					}
				}

				if skip {
					continue
				}
			}

			logrus.WithField("host", *vuln.HostInfo.Hostname).WithField("cve_score", vuln.Cve.BaseScore).
				WithField("severity", vuln.Cve.Severity).WithField("cve", *vuln.Cve.ID).
				Debug("adding vulnerability")

			deviceFinding := UserDeviceFinding{
				ProductName:    *vulnApp.ProductNameVersion,
				CveID:          *vuln.Cve.ID,
				CveSeverity:    vuln.Cve.Severity,
				TimestampFound: *vuln.CreatedTimestamp,
			}

			for _, mitigation := range vuln.Remediation.Entities {
				if strings.HasPrefix(strings.ToLower(*mitigation.Action), "no fix available for ") {
					continue
				}

				deviceFinding.Mitigations = appendUnique(deviceFinding.Mitigations, []string{*mitigation.Action})
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

			device.Tags = appendUnique(device.Tags, vuln.HostInfo.Tags)

			devices[uniqueDeviceID] = device

			hostTags = append(hostTags, device.Tags...)
		}
	}

	if len(devices) == 0 {
		return results, nil
	}

	if len(hostTags) == 0 {
		return nil, errors.New("no tags found on decices")
	}

	logrus.WithField("devices", len(devices)).Info("found vulnerable devices")

	for _, device := range devices {
		if len(device.Findings) == 0 {
			continue
		}

		hasMitigations := false
		for _, f := range device.Findings {
			if len(f.Mitigations) > 0 {
				hasMitigations = true
				break
			}
		}

		if !hasMitigations{
			logrus.WithField("device", device.MachineName).
				Debug("skipping device with vulnerabilities but no mitigations")
			continue
		}

		userEmail, err := findEmailTag(device.Tags, config.Email.Domains)
		if err != nil {
			logrus.
				WithError(err).
				WithField("tags", device.Tags).
				WithField("prefix", tagEmailPrefix).
				WithField("device", device.MachineName).
				Warn("could not extract Falcon email tag from host, using fallback")

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

	return results, nil
}
