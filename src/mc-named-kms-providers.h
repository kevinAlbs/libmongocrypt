/*
 * Copyright 2023-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MC_NAMED_KMS_PROVIDERS_H
#define MC_NAMED_KMS_PROVIDERS_H

// mc-named-kms-providers.h provides interfaces for storing and retrieving named KMS providers.

#include <bson/bson.h>               // bson_t
#include <mongocrypt-opts-private.h> // `_mongocrypt_opts_kms_*` types.
#include <mongocrypt.h>              // mongocrypt_status_t

typedef struct {
    char *key; // `key` stores "<prefix>:<name>". Example: "local:myname".
    _mongocrypt_kms_provider_t type;

    union {
        _mongocrypt_opts_kms_provider_azure_t azure;
        _mongocrypt_opts_kms_provider_gcp_t gcp;
        _mongocrypt_opts_kms_provider_aws_t aws;
        _mongocrypt_opts_kms_provider_local_t local;
        _mongocrypt_opts_kms_provider_kmip_t kmip;
    } value;
} _mongocrypt_named_kms_provider_t;

// `_mongocrypt_named_kms_provider_from_bson` returns NULL on error and sets an error status.
_mongocrypt_named_kms_provider_t *
_mongocrypt_named_kms_provider_new(const char *name, const bson_t *def, mongocrypt_status_t *status);
_mongocrypt_named_kms_provider_t *_mongocrypt_named_kms_provider_copy(const _mongocrypt_named_kms_provider_t *nkp);
void _mongocrypt_named_kms_provider_destroy(_mongocrypt_named_kms_provider_t *nkp);

typedef struct __mongocrypt_named_kms_provider_map_t _mongocrypt_named_kms_provider_map_t;

_mongocrypt_named_kms_provider_map_t *_mongocrypt_named_kms_provider_map_new(void);
void _mongocrypt_named_kms_provider_map_destroy(_mongocrypt_named_kms_provider_map_t *nkpm);
bool _mongocrypt_named_kms_provider_map_has(_mongocrypt_named_kms_provider_map_t *nkpm, const char *key);
// `mongocrypt_named_kms_provider_map_get` returns NULL if `name` is not in the map.
const _mongocrypt_named_kms_provider_t *
_mongocrypt_named_kms_provider_map_get(_mongocrypt_named_kms_provider_map_t *nkpm, const char *key);
// `mongocrypt_named_kms_provider_map_put` overwrites an entry if `nkp->name` is present in the map.
void _mongocrypt_named_kms_provider_map_put(_mongocrypt_named_kms_provider_map_t *nkpm,
                                            const _mongocrypt_named_kms_provider_t *nkp);

#endif // MC_NAMED_KMS_PROVIDERS_H
