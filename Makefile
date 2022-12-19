all: run

clean:
	rm slacker || true

build:
	go build -o slacker ./cmd/
	chmod +x slacker

run:
	go run ./cmd/ -dry -config=test.yml -log=trace
