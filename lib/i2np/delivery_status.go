package i2np

import (
	"time"
)

/*
I2P I2NP DeliveryStatus
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+----+----+----+----+
| msg_id            |           time_stamp                  |
+----+----+----+----+----+----+----+----+----+----+----+----+

msg_id :: Integer
       4 bytes
       unique ID of the message we deliver the DeliveryStatus for (see
       I2NPMessageHeader for details)

time_stamp :: Date
             8 bytes
             time the message was successfully created or delivered
*/

type DeliveryStatus struct {
	MessageID int
	Timestamp time.Time
}
