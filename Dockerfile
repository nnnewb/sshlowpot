FROM golang:1.19-bullseye AS BUILD
RUN mkdir -p /workspace
WORKDIR /workspace
COPY go.mod ./go.mod
COPY go.sum ./go.sum
COPY vendor ./vendor
COPY sshlowpot.go ./sshlowpot.go
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -mod=vendor -o sshlowpot sshlowpot.go

FROM scratch
COPY --from=BUILD /workspace/sshlowpot /sshlowpot
CMD [ "/sshlowpot","-d" ]
