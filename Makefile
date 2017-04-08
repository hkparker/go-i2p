fuzz:
	go-fuzz-build -o lib/common/fuzz/keys_and_cert/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/keys_and_cert
	go-fuzz-build -o lib/common/fuzz/certificate/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/certificate
	go-fuzz-build -o lib/common/fuzz/destination/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/destination
	go-fuzz-build -o lib/common/fuzz/router_address/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/router_address
	go-fuzz-build -o lib/common/fuzz/router_identity/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/router_identity
	go-fuzz-build -o lib/common/fuzz/string/exportable-fuzz.zip github.com/hkparker/go-i2p/lib/common/fuzz/string
	forego start
