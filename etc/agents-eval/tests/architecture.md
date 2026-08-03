# Architecture

## Prompt

How does libmongocrypt fit into the architecture of In-Use Encryption?

## Criteria

1. States libmongocrypt is a library used by MongoDB drivers, rather than something an application or the server uses directly.
2. States libmongocrypt performs no I/O itself.
3. States libmongocrypt acts as a state machine that the driver drives, performing the I/O requested at each state.
4. Identifies the MongoDB server (mongod / mongos) as a component contacted on libmongocrypt's behalf, to run the final command and/or fetch a remote schema.
5. Identifies KMS as a component, used to encrypt/decrypt the data encryption key (DEK) with a backing key encryption key (KEK) / master key.
6. Identifies mongocryptd and crypt_shared as interchangeable components, either of which does the query analysis for automatic encryption.
7. Notes crypt_shared is a library loaded in-process, whereas mongocryptd is a separate process the driver communicates with.
8. Notes that automatic encryption is an enterprise / Atlas only feature, while automatic decryption is not.
9. Notes that explicit encryption requires neither mongocryptd nor crypt_shared.
