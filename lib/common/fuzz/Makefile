fuzz:
	go-fuzz-build -o keys_and_cert/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/keys_and_cert
	go-fuzz-build -o certificate/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/certificate
	go-fuzz-build -o destination/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/destination
	go-fuzz-build -o router_address/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/router_address
	go-fuzz-build -o router_identity/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/router_identity
	go-fuzz-build -o string/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/string
	forego start
