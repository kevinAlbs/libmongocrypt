# Run a test requiring crypt_shared

## Prompt

Describe how to run the test: _test_encrypt_csfle_no_needs_markings

## Criteria

1. Notes that a real crypt_shared library is required, and that without one the test does not actually exercise anything.
2. Notes that `mongodl.py` from drivers-evergreen-tools can be used to download crypt_shared.
3. Gives the command to run a single test by passing its name to the `test-mongocrypt` executable.
4. Notes the test must be run from the source root, because test data is read via relative paths.
