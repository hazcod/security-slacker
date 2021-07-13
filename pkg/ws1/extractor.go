package ws1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/hazcod/crowdstrike-spotlight-slacker/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type WS1Result struct {
	Email string
	Devices []UserDevice
}

type UserDevice struct {
	MachineName string
	Compromised bool
	LastSeen  time.Time
	Findings    []UserDeviceFinding
}

type UserDeviceFinding struct {
	ComplianceName string
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func doAuthRequest(user, pass, apiKey, url, method string, payload interface{}) (respBytes []byte, err error) {
	var reqPayload []byte
	if payload != nil {
		if reqPayload, err = json.Marshal(&payload); err != nil {
			return nil, errors.Wrap(err, "coult not encode request body")
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(reqPayload))
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("aw-tenant-code", apiKey)
	req.Header.Set("Authorization", "Basic " + basicAuth(user, pass))

	httpClient := http.Client{
		Timeout:       time.Second * 10,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "http request failed")
	}

	if resp.StatusCode > 399 {
		respB, _ := ioutil.ReadAll(resp.Body)
		logrus.WithField("response", string(respB)).Warn("invalid response")
		return nil, errors.New("invalid response code: " + strconv.Itoa(resp.StatusCode))
	}

	defer resp.Body.Close()

	if respBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		return nil, errors.New("could not read response body")
	}

	return respBytes, nil
}

func GetMessages(config *config.Config, ctx context.Context) (map[string]WS1Result, error) {
	deviceResponseB, err := doAuthRequest(
		config.WS1.User, config.WS1.Password, config.WS1.APIKey,
		strings.TrimRight(config.WS1.Endpoint, "/") + "/mdm/devices/search?compliance_status=NonCompliant",
		http.MethodGet,
		nil,
	)

	if err != nil {
		return nil, errors.Wrap(err, "could not fetch WS1 devices")
	}

	var devicesResponse DevicesResponse
	if err := json.Unmarshal(deviceResponseB, &devicesResponse); err != nil {
		return nil, errors.Wrap(err, "could not deserialize getDevices call")
	}

	result := make(map[string]WS1Result)

	for _, device := range devicesResponse.Devices {
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
			if policy.CompliantStatus { continue }

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
			if shouldSkip { continue }

			userDevice.Findings = append(userDevice.Findings, UserDeviceFinding{
				ComplianceName: policy.PolicyName,
			})
		}

		ws1Result.Devices = append(ws1Result.Devices, userDevice)

		result[userEmail] = ws1Result
	}

	return result, nil
}
