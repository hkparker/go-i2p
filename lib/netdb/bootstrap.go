package netdb

type Reseed interface {
	// do reseed, return nil on success otherwise error
	// sends down all Netdb entries down chan
	// closes channel when done
	Reseed(chnl chan *Entry) error
}

func GetRandomReseed() Reseed {
	// TODO: hardcoded value
	return HTTPSReseed("https://i2p.rocks:445/")
}
