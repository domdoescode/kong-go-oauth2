.PHONY: all

build:
	docker run --rm -v $(PWD):/plugins kong-build build go-oauth2.go

run:
	docker build -t kong-go-oauth2 . && docker run --rm -p 8000:8000 kong-go-oauth2

run-raw:
	docker build -t kong-go-oauth2 -f Dockerfile.better . && docker run --rm -p 8000:8000 kong-go-oauth2
