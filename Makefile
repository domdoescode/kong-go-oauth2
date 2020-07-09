.PHONY: all

run:
	docker build -t kong-go-oauth2 . && docker run --rm -p 8000:8000 kong-go-oauth2
