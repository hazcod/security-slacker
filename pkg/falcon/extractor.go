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

func remove(a []string, i int) []string {
	a[i] = a[len(a)-1] // Copy last element to index i.
	a[len(a)-1] = ""   // Erase last element (write zero value).
	a = a[:len(a)-1]   // Truncate slice.
	return a
}

func removeFinding(a []UserDeviceFinding, i int) []UserDeviceFinding {
	a[i] = a[len(a)-1] // Copy last element to index i.
	a[len(a)-1] = UserDeviceFinding{}  // Erase last element (write zero value).
	a = a[:len(a)-1]   // Truncate slice.
	return a
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
			Filter:  "status:'open'",
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

	var mitigationIDs []string

	for _, vuln := range getResult.GetPayload().Resources {

		if len(vuln.Remediation.Ids) == 0 && config.Falcon.SkipNoMitigation {
			logrus.WithField("app", *vuln.App.ProductNameVersion).
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
				logrus.WithField("cve", *vuln.Cve.ID).WithField("host", *vuln.HostInfo.Hostname).
					Warn("skipping CVE")
				continue
			}
		}

		mitigationIDs = appendUnique(mitigationIDs, vuln.Remediation.Ids)

		uniqueDeviceID, err := getUniqueDeviceID(*vuln.HostInfo)
		if err != nil {
			logrus.WithError(err).Error("could not calculate unique device id")

			continue
		}

		if config.Falcon.MinCVEBaseScore > 0 {
			if int(*vuln.Cve.BaseScore) < config.Falcon.MinCVEBaseScore {
				logrus.WithField("cve_score", *vuln.Cve.BaseScore).Debug("skipping vulnerability")
				continue
			}
		}

		if len(config.Falcon.SkipSeverities) > 0 {
			vulnSev := strings.ToLower(*vuln.Cve.Severity)
			skip := false

			for _, sev := range config.Falcon.SkipSeverities {
				if strings.EqualFold(sev, vulnSev) {
					logrus.WithField("host", *vuln.HostInfo.Hostname).WithField("cve_score", *vuln.Cve.BaseScore).
						WithField("severity", *vuln.Cve.Severity).WithField("cve", *vuln.Cve.ID).
						Debug("skipping vulnerability")
					skip = true
					break
				}
			}

			if skip { continue }
		}

		logrus.WithField("host", *vuln.HostInfo.Hostname).WithField("cve_score", *vuln.Cve.BaseScore).
			WithField("severity", *vuln.Cve.Severity).WithField("cve", *vuln.Cve.ID).
			Debug("adding vulnerability")

		deviceFinding := UserDeviceFinding{
			ProductName:         *vuln.App.ProductNameVersion,
			CveID:               *vuln.Cve.ID,
			CveSeverity:         *vuln.Cve.Severity,
			TimestampFound:      *vuln.CreatedTimestamp,
			Mitigations:		 vuln.Remediation.Ids,
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

	if len(devices) == 0 {
		return results, nil
	}

	if len(hostTags) == 0 {
		return nil, errors.New("no tags found on decices")
	}

	logrus.WithField("remediations", len(mitigationIDs)).Debug("retrieving remediations")

	remResp, err := client.SpotlightVulnerabilities.GetRemediationsV2(&spotlight_vulnerabilities.GetRemediationsV2Params{
		Ids:        mitigationIDs,
		Context:    ctx,
	})

	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve remediations")
	}

	remediations := make(map[string]string)

	for _, remRes := range remResp.GetPayload().Resources {
		logrus.Tracef("%s -> %s", *remRes.ID, *remRes.Action)
		remediations[*remRes.ID] = *remRes.Action
	}

	// remove useless mitigations that start with 'no fix available for'
	for a, device := range devices {
		for b, finding := range device.Findings {
			for c, rem := range finding.Mitigations {
				remText, remFound := remediations[rem]

				if !remFound || strings.HasPrefix(strings.ToLower(remText), "no fix available for") {
					logrus.WithField("rem", rem).WithField("rem_text", remText).WithField("device", device.MachineName).
						Warn("skipping mitigation")

					devices[a].Findings[b].Mitigations = remove(finding.Mitigations, c)
					continue
				}

				finding.Mitigations[c] = remText
			}
		}
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
