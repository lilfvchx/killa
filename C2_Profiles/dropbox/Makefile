BINARY_NAME?=main

build:
	go mod download
	go mod tidy
	CGO_ENABLED=0 go build -o ${BINARY_NAME} .
	CGO_ENABLED=0 go build -o server ./server
	cp ${BINARY_NAME} /
	cp server /

run:
	cp /${BINARY_NAME} .
	./${BINARY_NAME}
