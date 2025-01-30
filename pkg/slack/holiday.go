package slack

import (
	"github.com/slack-go/slack"
	"strings"
)

var (
	slackStatusHolidays = []string{
		"vacationing",
		"absent",
	}
)

func IsOnHoliday(user slack.User) bool {
	slackStatus := strings.ToLower(user.Profile.StatusText)

	for _, statusPrefix := range slackStatusHolidays {
		if strings.HasPrefix(slackStatus, statusPrefix) {
			return true
		}
	}

	return false
}
