BINARY_NAME?=main
SERVER_BINARY_NAME?=server.bin

build:
	go mod download
	go mod tidy
	CGO_ENABLED=0 go build -o ${BINARY_NAME} .
	CGO_ENABLED=0 go build -o ${SERVER_BINARY_NAME} ./server
	cp ${BINARY_NAME} /
	cp ${SERVER_BINARY_NAME} /server

run:
	cp /${BINARY_NAME} .
	./${BINARY_NAME}
