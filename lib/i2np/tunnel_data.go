package i2np

/*
I2P I2NP TunnelData
https://geti2p.net/spec/i2np
Accurate for version 0.9.28


+----+----+----+----+----+----+----+----+
|     tunnnelID     | data              |
+----+----+----+----+                   |
|                                       |
~                                       ~
~                                       ~
|                                       |
+                   +----+----+----+----+
|                   |
+----+----+----+----+

tunnelId ::
         4 byte TunnelId
         identifies the tunnel this message is directed at

data ::
     1024 bytes
     payload data.. fixed to 1024 bytes
*/

type TunnelData [1028]byte
