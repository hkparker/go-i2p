package crypto

type AesCBC struct {
}

type AesECB struct {
}


type TunnelKey [32]byte
type TunnelIV [16]byte

//
// tunnel aes base
//
type TunnelAes struct {
  layerKey TunnelKey
  ivKey TunnelKey
  iv TunnelIV
}

type TunnelEncryption struct {
  TunnelAes
}

type TunnelDecryption struct {
  TunnelAes
}
