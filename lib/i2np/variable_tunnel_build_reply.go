package i2np

/*
I2P I2NP VariableTunnelBuildReply
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
| num| BuildResponseRecords...
+----+----+----+----+----+----+----+----+

Same format as VariableTunnelBuildMessage, with BuildResponseRecords.
*/

type VariableTunnelBuildReply struct {
	Count                int
	BuildResponseRecords []BuildResponseRecord
}
