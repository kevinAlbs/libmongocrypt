# libbson provenance

## Prompt
Do I need to install libbson before building libmongocrypt?

## Criteria
1. States libbson does not need to be installed: it is fetched at configure time by `cmake/FetchMongoC.cmake`.
2. States the fetched libbson is statically linked into libmongocrypt by default.
3. Notes `USE_SHARED_LIBBSON=ON` links an installed libbson instead.
