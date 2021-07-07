

clean:
	rm slacker || true

build:
	go build -o slacker ./cmd/
	chmod +x slacker
