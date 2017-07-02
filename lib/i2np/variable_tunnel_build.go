package i2np

/*
I2P I2NP VariableTunnelBuild
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
| num| BuildRequestRecords...
+----+----+----+----+----+----+----+----+

Same format as TunnelBuildMessage, except for the addition of a $num field
in front and $num number of BuildRequestRecords instead of 8

num ::
       1 byte Integer
       Valid values: 1-8

record size: 528 bytes
total size: 1+$num*528
*/

type VariableTunnelBuild struct {
	Count               int
	BuildRequestRecords []BuildRequestRecord
}
