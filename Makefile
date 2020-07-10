.PHONY: all run release

run:
	docker build -t kong-go-oauth2 . && docker run --rm -it -p 8000:8000 kong-go-oauth2

release:
	cp -R ./vendor ./build
	cp go-google-oauth2.go ./build
	tar -czvf ./release/kong-go-oauth2-${VERSION}.tar.gz ./build
	ghr -t ${GITHUB_TOKEN} -u domudall -r kong-go-oauth2 -delete ${VERSION} ./release/kong-go-oauth2-${VERSION}.tar.gz