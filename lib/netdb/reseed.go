package netdb

type HTTPSReseed string

func (r HTTPSReseed) Reseed(chnl chan *Entry) (err error) {
  close(chnl)
  return
}
