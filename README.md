# crowdstrike-spotlight-slacker
Nags users on Slack about outstanding application vulnerabilities found by Crowdstrike Spotlight so they patch their software.

![slack example](.github/readme/screenshot.png)

## Instructions

1. Tag your Falcon hosts with `email/user/company/com` if their email is `user@company.com`.
2. Fetch a binary release or Docker image from [Releases](https://github.com/hazcod/crowdstrike-spotlight-slacker/releases).
3. Create a Falcon API token to use in `API Clients and Keys` with `Read` permission to `Hosts` and `Spotlight`.
4. Create a Slack app and get the bot token.
5. Create a configuration file:

```yaml
slack:
  # slack bot token
  token: "XXX"
  # Slack user that receives  messages if the user is not found
  security_user: "security@mycompany.com"

falcon:
  clientid: "XXX"
  secret: "XXX"
  cloud_region: "eu-1"
  # skip vulnerabilities without patches available
  skip_no_mitigation: true

email:
  # email domain
  domain: "mycompany"

# what is sent to the user in Go templating
templates:
  user_message: |
    *:warning:  We found security vulnerabilities on your device(s)*
    Hi {{ .Slack.Profile.FirstName }} {{ .Slack.Profile.LastName }}! One or more of your devices seem to be vulnerable.
    Luckily we noticed there are patches available. :tada:
    Can you please update following software as soon as possible?

    {{ range $device := .User.Devices }}
    :computer: {{ $device.MachineName }}
    {{ range $vuln := $device.Findings }}
      `{{ $vuln.ProductName }}`
    {{ end }}
    {{ end }}

    Please update them as soon as possible. In case of any issues, hop into *#security*.
    Thank you! :wave:

  security_overview_message: |
    :information_source: *Device Posture overview* {{ .Date.Format "Jan 02, 2006 15:04:05 UTC" }}

    {{ if not .Results }}Nothing to report!  :white_check_mark: {{ else }}
    {{ range $result := .Results }}
    :man-surfing: *{{ $result.Email }}*
    {{ range $device := $result.Devices }}
      :computer: {{ $device.MachineName}}
      {{ range $vuln := $device.Findings }}- {{ $vuln.ProductName }} ({{ $vuln.CveSeverity }}) ({{ $vuln.TimestampFound }}) ({{ $vuln.CveID }}){{ end }}
    {{ end }}
    {{ end }}
    {{ end }}

    {{ if .Errors }}
    :warning: *Errors:*
    {{ range $err := .Errors }}
    - {{ $err }}
    {{ end }}
    {{ end }}
```
4. Run `css -config=your-config.yml`.
5. See it popup in Slack!
