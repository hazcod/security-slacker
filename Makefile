all: run

clean:
	rm -r dist/ || true

build:
	goreleaser --config=.github/goreleaser.yml build --snapshot --clean

run:
	go run ./cmd/ -dry -config=test.yml -log=trace
