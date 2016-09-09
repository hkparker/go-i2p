# Contributing

Thanks for taking a look at go-i2p!  Please reach out if you have any questions or need help getting started.

## Getting Starting

Install required dependencies

This example assumes Ubuntu 16.04

```sh
sudo apt-get install pkg-config libsodium-dev
go get github.com/hkparker/go-i2p
go get github.com/sirupsen/logrus
go get github.com/stretchr/testify/assert
```

Fork go-i2p and clone it into your workspace.  Make sure you can execute `go test ./...` in the project's root directory.  At that point you should have everything you need to start making changes and opening pull requests.  If you aren't sure what to work on, take a look at some good [getting started issues](https://github.com/hkparker/go-i2p/issues?q=is%3Aopen+is%3Aissue+label%3A%22start+here%22).

## I2P Specifications

The I2P community maintains up-to-date [specifications](https://geti2p.net/spec) of most of the application, which are being used to create go-i2p.  Currently, most the of common data structures (located in `lib/common/`) have been implemented and tested, and serve as good examples.

## Testing

`go test ./...`

## Conventions

#### Logging

Logrus is used for logging across all of go-i2p.  All log statements should contain an `at` fields and a `reason` field.  Here is a good example from the go-i2p implementation of a LeaseSet:

```go
log.WithFields(log.Fields(
	"at":           "(LeaseSet) PublicKey",
	"data_len":     remainer_len,
	"required_len": LEASE_SET_PUBKEY_SIZE,
	"reason":       "not enough data",
)).Error("error parsing public key")
```

#### Testing

Testify is used to assert test cases in all tests in go-i2p for simplicity.  Here is an example from the RouterInfo tests:

```go
func TestRouterAddressCountReturnsCorrectCount(t *testing.T) {
	assert := assert.New(t)

	router_info := buildFullRouterInfo()
	count, err := router_info.RouterAddressCount()
	assert.Nil(err)
	assert.Equal(1, count, "RouterInfo.RouterAddressCount() did not return correct count")
}
```

## Pull Requests

Pull requests should pass all tests, test all new behavior, and be correctly formatted by `gofmt` before merge.  Feel free to open incomplete pull requests if you are struggling, I will enthusiasticlly help you complete the PR in any way needed.
