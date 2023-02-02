package ws1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/hazcod/crowdstrike-spotlight-slacker/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2/clientcredentials"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	rgxCommaNumber = regexp.MustCompile(`(\.\d+)$`)
)

type WS1Result struct {
	Email   string
	Devices []UserDevice
}

type UserDevice struct {
	MachineName string
	Compromised bool
	LastSeen    time.Time
	Findings    []UserDeviceFinding
}

type UserDeviceFinding struct {
	ComplianceName string
}

func doAuthRequest(ctx context.Context, ws1AuthLocation, clientID, secret, url, method string, payload interface{}) (respBytes []byte, err error) {
	var reqPayload []byte
	if payload != nil {
		if reqPayload, err = json.Marshal(&payload); err != nil {
			return nil, errors.Wrap(err, "coult not encode request body")
		}
	}

	oauth2Config := clientcredentials.Config{ClientID: clientID, ClientSecret: secret,
		TokenURL: fmt.Sprintf("https://%s.uemauth.vmwservices.com/connect/token", ws1AuthLocation)}
	httpClient := oauth2Config.Client(ctx)
	httpClient.Timeout = time.Second * 30

	req, err := http.NewRequest(method, url, bytes.NewReader(reqPayload))
	req = req.WithContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}

	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "http request failed")
	}

	if resp.StatusCode > 399 {
		respB, _ := io.ReadAll(resp.Body)
		logrus.WithField("response", string(respB)).Warn("invalid response")
		return nil, errors.New("invalid response code: " + strconv.Itoa(resp.StatusCode))
	}

	defer resp.Body.Close()

	if respBytes, err = io.ReadAll(resp.Body); err != nil {
		return nil, errors.New("could not read response body")
	}

	return respBytes, nil
}

func GetMessages(config *config.Config, ctx context.Context) (map[string]WS1Result, []string, []error, error) {
	deviceResponseB, err := doAuthRequest(
		ctx,
		config.WS1.AuthLocation, config.WS1.ClientID, config.WS1.ClientSecret,
		strings.TrimRight(config.WS1.Endpoint, "/")+"/mdm/devices/search?compliance_status=NonCompliant",
		http.MethodGet,
		nil,
	)

	var securityErrors []error

	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "could not fetch WS1 devices")
	}

	usersWithDevices := make([]string, 0)

	var devicesResponse DevicesResponse
	if err := json.Unmarshal(deviceResponseB, &devicesResponse); err != nil {
		return nil, nil, nil, errors.Wrap(err, "could not deserialize getDevices call")
	}

	securityErrorsMap := make(map[string]struct{})

	now := time.Now()
	result := make(map[string]WS1Result)

	for _, device := range devicesResponse.Devices {

		// add an error if a device has not been seen for over a month
		lastSeen := rgxCommaNumber.ReplaceAllString(device.LastSeen, "")
		hostLastSeen, err := time.Parse("2006-01-02T15:04:05", lastSeen)
		if err != nil {
			logrus.WithError(err).WithField("timestamp", lastSeen).
				WithField("device", device.DeviceFriendlyName).Error("could not parse MDM host last seen")
		}

		if hostLastSeen.Before(now.Add(-2 * time.Hour * 24 * 31)) {
			securityErrorsMap[fmt.Sprintf("%s has not been seen for over 2 months in MDM: %s", device.DeviceFriendlyName, lastSeen)] = struct{}{}
		}

		usersWithDevices = append(usersWithDevices, strings.ToLower(device.UserEmailAddress))

		if strings.EqualFold(device.ComplianceStatus, "Compliant") {
			continue
		}

		userEmail := strings.ToLower(device.UserEmailAddress)

		ws1Result, ok := result[userEmail]
		if !ok {
			ws1Result = WS1Result{Devices: []UserDevice{}, Email: strings.ToLower(userEmail)}
		}

		lastSeenDate, err := time.Parse("2006-01-02T15:04:05", device.LastSeen)
		if err != nil {
			logrus.WithError(err).WithField("last_seen", device.LastSeen).
				WithField("device", device.DeviceFriendlyName).Error("could not parse device last seen")
			lastSeenDate = time.Now()
		}

		userDevice := UserDevice{
			MachineName: device.DeviceFriendlyName,
			Compromised: device.CompromisedStatus,
			LastSeen:    lastSeenDate,
		}

		for _, policy := range device.ComplianceSummary.DeviceCompliance {
			if policy.CompliantStatus {
				continue
			}

			shouldSkip := false
			for _, filter := range config.WS1.SkipFilters {
				if filter.Policy != "" && !strings.EqualFold(policy.PolicyName, filter.Policy) {
					continue
				}
				if filter.User != "" && !strings.EqualFold(filter.User, userEmail) {
					continue
				}
				shouldSkip = true
			}
			if shouldSkip {
				continue
			}

			userDevice.Findings = append(userDevice.Findings, UserDeviceFinding{
				ComplianceName: policy.PolicyName,
			})
		}

		ws1Result.Devices = append(ws1Result.Devices, userDevice)

		result[userEmail] = ws1Result
	}

	for key, _ := range securityErrorsMap {
		securityErrors = append(securityErrors, errors.New(key))
	}

	return result, usersWithDevices, securityErrors, nil
}
