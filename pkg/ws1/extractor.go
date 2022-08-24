package ws1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/hazcod/crowdstrike-spotlight-slacker/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
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

type LoggedRoundTripper struct {
	Proxied http.RoundTripper
	Logger  *logrus.Logger
}

func (t LoggedRoundTripper) RoundTrip(req *http.Request) (res *http.Response, e error) {
	resp, err := t.Proxied.RoundTrip(req)

	if t.Logger != nil && t.Logger.IsLevelEnabled(logrus.TraceLevel) {
		dumped, err := httputil.DumpRequest(req, true)
		if err != nil {
			t.Logger.WithError(err).Error("could not dump http request")
		} else {
			t.Logger.Trace(string(dumped))
		}

		if req.Response == nil {
			t.Logger.Trace("No response")
		} else {
			dumped, err = httputil.DumpResponse(req.Response, true)
			if err != nil {
				t.Logger.WithError(err).Error("could not dump http response")
			} else {
				t.Logger.Trace(string(dumped))
			}
		}
	}

	return resp, err
}

type authResponse struct {
	Token   string `json:"access_token"`
	Expires int    `json:"expires_in"`
	Type    string `json:"token_type"`
}

func renewAuth(_ context.Context, ws1AuthLocation, clientID, secret string) (token string, expiry time.Time, err error) {
	data := url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"grant_type":    {"client_credentials"},
	}

	resp, err := http.PostForm(fmt.Sprintf("https://%s.uemauth.vmwservices.com/connect/token", ws1AuthLocation), data)
	if err != nil {
		return "", time.Time{}, errors.Wrap(err, "could not post to token endpoint")
	}

	if resp.StatusCode > 399 {
		return "", time.Time{}, errors.Errorf("token endpoint returned status code: %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	respB, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, errors.Wrap(err, "could not read token response")
	}

	logrus.Debugf("%s", string(respB))

	var response authResponse
	if err := json.Unmarshal(respB, &response); err != nil {
		return "", time.Time{}, errors.Wrap(err, "could not decode token response")
	}

	if !strings.EqualFold(response.Type, "bearer") {
		return "", time.Time{}, errors.Wrap(err, "not a bearer token")
	}

	if response.Expires <= 0 {
		return "", time.Time{}, errors.New("empty expires returned")
	}

	if response.Token == "" {
		return "", time.Time{}, errors.New("no token returned")
	}

	timeExpires := time.Now().Add(time.Second * time.Duration(response.Expires))

	if timeExpires.Before(time.Now()) {
		return "", time.Time{}, errors.New("token retrieved is already expired")
	}

	return response.Token, timeExpires, nil
}

func doAuthRequest(ctx context.Context, ws1AuthLocation, clientID, secret, url, method string, payload interface{}) (respBytes []byte, err error) {
	var reqPayload []byte
	if payload != nil {
		if reqPayload, err = json.Marshal(&payload); err != nil {
			return nil, errors.Wrap(err, "coult not encode request body")
		}
	}

	token, _, err := renewAuth(ctx, ws1AuthLocation, clientID, secret)
	if err != nil {
		return nil, errors.Wrap(err, "could not renew auth")
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(reqPayload))
	req = req.WithContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	httpClient := http.Client{Timeout: time.Second * 10}
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

func GetMessages(config *config.Config, ctx context.Context) (map[string]WS1Result, []string, error) {
	deviceResponseB, err := doAuthRequest(
		ctx,
		config.WS1.AuthLocation, config.WS1.ClientID, config.WS1.ClientSecret,
		strings.TrimRight(config.WS1.Endpoint, "/")+"/mdm/devices/search?compliance_status=NonCompliant",
		http.MethodGet,
		nil,
	)

	if err != nil {
		return nil, nil, errors.Wrap(err, "could not fetch WS1 devices")
	}

	usersWithDevices := make([]string, 0)

	var devicesResponse DevicesResponse
	if err := json.Unmarshal(deviceResponseB, &devicesResponse); err != nil {
		return nil, nil, errors.Wrap(err, "could not deserialize getDevices call")
	}

	result := make(map[string]WS1Result)

	for _, device := range devicesResponse.Devices {
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

	return result, usersWithDevices, nil
}
