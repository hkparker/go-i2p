package common

import "testing"

func TestTimeFromMiliseconds(t *testing.T) {
	next_day := Date{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
	go_time := next_day.Time()
	if go_time.Unix() != 86400 {
		t.Fatal("Date.Time() did not parse time in milliseconds")
	}
}
