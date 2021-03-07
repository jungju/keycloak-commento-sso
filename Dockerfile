FROM  golang:1.16-buster as builder

WORKDIR /tmp/app
COPY . .

RUN go mod tidy \
    && go get -u -d -v ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o app main.go

FROM scratch
COPY --from=builder /tmp/app /
CMD ["/app"]