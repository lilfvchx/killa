FROM golang:1.22 as builder

WORKDIR /Mythic/

COPY [".", "."]

RUN make build

FROM alpine

RUN apk add make

COPY --from=builder /main /main
COPY --from=builder /server /Mythic/server

WORKDIR /Mythic/

COPY [".", "."]

CMD make run
