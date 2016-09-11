package common

/*
I2P Lease
https://geti2p.net/spec/common-structures#lease
Accurate for version 0.9.24

+----+----+----+----+----+----+----+----+
| tunnel_gw                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|     tunnel_id     |      end_date
+----+----+----+----+----+----+----+----+
                    |
+----+----+----+----+

tunnel_gw :: Hash of the RouterIdentity of the tunnel gateway
             length -> 32 bytes

tunnel_id :: TunnelId
             length -> 4 bytes

end_date :: Date
            length -> 8 bytes
*/

// Sizes or various components of a Lease
const (
	LEASE_SIZE           = 44
	LEASE_HASH_SIZE      = 32
	LEASE_TUNNEL_ID_SIZE = 4
)

type Lease [LEASE_SIZE]byte

//
// Return the first 32 bytes of the Lease as a Hash.
//
func (lease Lease) TunnelGateway() (hash Hash) {
	copy(hash[:], lease[:LEASE_HASH_SIZE])
	return
}

//
// Parse the TunnelID Integer in the Lease.
//
func (lease Lease) TunnelID() uint32 {
	return uint32(
		Integer(lease[LEASE_HASH_SIZE : LEASE_HASH_SIZE+LEASE_TUNNEL_ID_SIZE]),
	)
}

//
// Return the Date inside the Lease.
//
func (lease Lease) Date() (date Date) {
	copy(date[:], lease[LEASE_HASH_SIZE+LEASE_TUNNEL_ID_SIZE:])
	return
}
