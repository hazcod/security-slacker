clean:
	rm slacker || true

build:
	go build -o slacker ./cmd/
	chmod +x slacker

run:
	chmod +x slacker
	./slacker -dry -config=test.yml
