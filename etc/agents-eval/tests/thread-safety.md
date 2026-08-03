# Thread safety and object lifetimes

## Prompt

Describe thread-safety of libmongocrypt objects.

## Criteria

1. States `mongocrypt_t` is thread-safe.
2. States `mongocrypt_ctx_t` is not thread-safe.
3. Notes a `mongocrypt_ctx_t` represents a single operation (encrypt, decrypt, data key creation, ...), so each operation gets its own.
4. Notes a `mongocrypt_t` is expected to be owned by the driver's `MongoClient` / `ClientEncryption` object, i.e. one long-lived handle rather than one per operation.
