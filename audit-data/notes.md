
# Genral notes

- Each vault works with one token.

# How signing a transaction works:
1. Take private key + message (data, function selector, parameters)
2. Put this through elliptic curve digital signature algorithm
   1. This outputs v, r, and s
   2. We can use these values to verify someone's signature using ecrecover

# How verification works:
1. Get the signed message
   1. Break into v, r, s
2. Get the data the sender signed
   1. Format the data to the EIP standard
3. Use it as input parameters for `ecrrecover`