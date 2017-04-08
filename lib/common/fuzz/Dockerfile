FROM golang

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install libsodium-dev -y

RUN go get github.com/dvyukov/go-fuzz/go-fuzz
RUN go get github.com/dvyukov/go-fuzz/go-fuzz-build
RUN go get github.com/hkparker/go-i2p

WORKDIR /go/src/github.com/hkparker/go-i2p

ENTRYPOINT ["make", "fuzz"]
