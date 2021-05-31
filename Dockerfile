FROM golang:1.16-alpine AS builder

ENV CGO_ENABLED=0

# add ca certificates and timezone data files
# hadolint ignore=DL3018
RUN apk add -U --no-cache ca-certificates tzdata

# add unprivileged user
RUN adduser -s /bin/true -u 1000 -D -h /app app \
  && sed -i -r "/^(app|root)/!d" /etc/group /etc/passwd \
  && sed -i -r 's#^(.*):[^:]*$#\1:/sbin/nologin#' /etc/passwd

WORKDIR /go/src/app/

COPY go.mod go.sum /go/src/app/
RUN go mod download

COPY . /go/src/app
RUN go build -trimpath -ldflags '-w -s -extldflags "-static"' -o /app /go/src/app/cmd/ \
  && chmod +x /app/cmd

#
# ---
#

# start with empty image
FROM scratch

# add-in our timezone data file
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# add-in our unprivileged user
COPY --from=builder /etc/passwd /etc/group /etc/shadow /etc/

# add-in our ca certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder --chown=app /app/cmd /app

# from now on, run as the unprivileged user
USER app

# entrypoint
ENTRYPOINT ["/app"]
