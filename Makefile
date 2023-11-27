DOCKER_USERNAME ?= DarkMukke
APPLICATION_NAME ?= iw_svc_identity

go:
	go build
build:
	docker build --tag ${DOCKER_USERNAME}/${APPLICATION_NAME} .
push:
	docker push ${DOCKER_USERNAME}/${APPLICATION_NAME}