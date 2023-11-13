/*
 * Copyright 2021-present MongoDB, Inc.
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

#include <mongocrypt-opts-private.h> // Declares structs implemented in this file.

#include <mongocrypt-crypto-private.h> // MONGOCRYPT_KEY_LEN
#include <mongocrypt-private.h>        // CLIENT_ERR

#define KEY_HELP "Must be of form `<provider type>:<name>`. Example: `local:name`."

// `mc_named_provider_parse_key` tries to parse `key` as the form `<prefix>:<name`> and sets `prefix_out` and
// `name_out` to copies that must be freed. On failure, `prefix_out` and `name_out` are set to NULL.
bool mc_named_provider_parse_key(const char *key, char **prefix_out, char **name_out, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(key);
    BSON_ASSERT_PARAM(prefix_out);
    BSON_ASSERT_PARAM(name_out);
    BSON_ASSERT(status || true); // Optional.

    *prefix_out = NULL;
    *name_out = NULL;
    // Parse `key` into `prefix` and `name`.
    {
        const char *prefix_end = strstr(key, ":");
        if (prefix_end == NULL) {
            CLIENT_ERR("invalid KMS provider `%s`: missing colon. " KEY_HELP, key);
            return false;
        }
        const char *next_colon = strstr(prefix_end + 1, ":");
        if (next_colon != NULL) {
            CLIENT_ERR("invalid KMS provider `%s`: extra colon. " KEY_HELP, key);
            return false;
        }

        *prefix_out = bson_strndup(key, prefix_end - key);
        if (0 == strlen(*prefix_out)) {
            CLIENT_ERR("invalid KMS provider `%s`: empty prefix. " KEY_HELP, key);
            return false;
        }

        *name_out = bson_strdup(prefix_end + 1);
        if (0 == strlen(*name_out)) {
            CLIENT_ERR("invalid KMS provider `%s`: empty name. " KEY_HELP, key);
            return false;
        }
    }
    return true;
}

// `_mongocrypt_named_kms_provider_from_bson` returns NULL on error and sets an error status.
mc_named_kms_provider_t *mc_named_kms_provider_new(const char *key, const bson_t *def, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(key);
    BSON_ASSERT_PARAM(def);
    BSON_ASSERT(status || true); // Optional.

    char *prefix = NULL;
    char *name = NULL;
    mc_named_kms_provider_t *nkp = bson_malloc0(sizeof(mc_named_kms_provider_t));
    bool ok = false;

    nkp->key = bson_strdup(key);

    if (!mc_named_provider_parse_key(key, &prefix, &name, status)) {
        goto fail;
    }

    if (0 == strcmp(prefix, "aws")) {
        // Set `type` first. If an error occurs the `value` union may be partly constructed and need cleanup.
        nkp->type = MONGOCRYPT_KMS_PROVIDER_AWS;

        if (!_mongocrypt_parse_required_utf8(def, "accessKeyId", &nkp->value.aws.access_key_id, status)) {
            goto fail;
        }
        if (!_mongocrypt_parse_required_utf8(def, "secretAccessKey", &nkp->value.aws.secret_access_key, status)) {
            goto fail;
        }

        if (!_mongocrypt_parse_optional_utf8(def, "sessionToken", &nkp->value.aws.session_token, status)) {
            goto fail;
        }

        if (!_mongocrypt_check_allowed_fields(def,
                                              NULL /* use root */,
                                              status,
                                              "accessKeyId",
                                              "secretAccessKey",
                                              "sessionToken")) {
            goto fail;
        }

    } else if (0 == strcmp(prefix, "azure")) {
        // Set `type` first. If an error occurs the `value` union may be partly constructed and need cleanup.
        nkp->type = MONGOCRYPT_KMS_PROVIDER_AZURE;
        if (!_mongocrypt_parse_optional_utf8(def, "accessToken", &nkp->value.azure.access_token, status)) {
            goto fail;
        }

        if (nkp->value.azure.access_token) {
            // Caller provided an accessToken directly.
            if (!_mongocrypt_check_allowed_fields(def, NULL /* use root */, status, "accessToken")) {
                goto fail;
            }
            goto succeed;
        }

        // No accessToken given. Fetch an accessToken later using the Azure API.
        if (!_mongocrypt_parse_required_utf8(def, "tenantId", &nkp->value.azure.tenant_id, status)) {
            goto fail;
        }

        if (!_mongocrypt_parse_required_utf8(def, "clientId", &nkp->value.azure.client_id, status)) {
            goto fail;
        }

        if (!_mongocrypt_parse_required_utf8(def, "clientSecret", &nkp->value.azure.client_secret, status)) {
            goto fail;
        }

        if (!_mongocrypt_parse_optional_endpoint(def,
                                                 "identityPlatformEndpoint",
                                                 &nkp->value.azure.identity_platform_endpoint,
                                                 NULL /* opts */,
                                                 status)) {
            goto fail;
        }

        if (!_mongocrypt_check_allowed_fields(def,
                                              NULL /* use root */,
                                              status,
                                              "tenantId",
                                              "clientId",
                                              "clientSecret",
                                              "identityPlatformEndpoint")) {
            goto fail;
        }

    } else if (0 == strcmp(prefix, "gcp")) {
        // Set `type` first. If an error occurs the `value` union may be partly constructed and need cleanup.
        nkp->type = MONGOCRYPT_KMS_PROVIDER_GCP;

        if (!_mongocrypt_parse_optional_utf8(def, "accessToken", &nkp->value.gcp.access_token, status)) {
            goto fail;
        }

        if (nkp->value.gcp.access_token) {
            // Caller provided an accessToken directly.
            if (!_mongocrypt_check_allowed_fields(def, NULL /* use root */, status, "accessToken")) {
                goto fail;
            }
            goto succeed;
        }

        // No accessToken given. Fetch an accessToken later using the GCP API.
        if (!_mongocrypt_parse_required_utf8(def, "email", &nkp->value.gcp.email, status)) {
            goto fail;
        }

        if (!_mongocrypt_parse_required_binary(def, "privateKey", &nkp->value.gcp.private_key, status)) {
            goto fail;
        }

        if (!_mongocrypt_parse_optional_endpoint(def, "endpoint", &nkp->value.gcp.endpoint, NULL /* opts */, status)) {
            goto fail;
        }

        if (!_mongocrypt_check_allowed_fields(def, NULL /* use root */, status, "email", "privateKey", "endpoint")) {
            goto fail;
        }

    } else if (0 == strcmp(prefix, "kmip")) {
        // Set `type` first. If an error occurs the `value` union may be partly constructed and need cleanup.
        nkp->type = MONGOCRYPT_KMS_PROVIDER_KMIP;
        _mongocrypt_endpoint_parse_opts_t opts = {0};

        opts.allow_empty_subdomain = true;
        if (!_mongocrypt_parse_required_endpoint(def, "endpoint", &nkp->value.kmip.endpoint, &opts, status)) {
            goto fail;
        }

        if (!_mongocrypt_check_allowed_fields(def, NULL /* use root */, status, "endpoint")) {
            goto fail;
        }
    } else if (0 == strcmp(prefix, "local")) {
        // Set `type` first. If an error occurs the `value` union may be partly constructed and need cleanup.
        nkp->type = MONGOCRYPT_KMS_PROVIDER_LOCAL;
        if (!_mongocrypt_parse_required_binary(def, "key", &nkp->value.local.key, status)) {
            goto fail;
        }

        if (nkp->value.local.key.len != MONGOCRYPT_KEY_LEN) {
            CLIENT_ERR("local key must be %d bytes, got %" PRId32, MONGOCRYPT_KEY_LEN, nkp->value.local.key.len);
            goto fail;
        }

        if (!_mongocrypt_check_allowed_fields(def, NULL /* use root */, status, "key")) {
            goto fail;
        }
    } else {
        CLIENT_ERR("invalid KMS provider `%s`: unknown prefix `%s`. " KEY_HELP, key, prefix);
        goto fail;
    }

succeed:
    ok = true;
fail:
    if (!ok) {
        mc_named_kms_provider_destroy(nkp);
        nkp = NULL;
    }
    bson_free(name);
    bson_free(prefix);
    return nkp;
}

mc_named_kms_provider_t *mc_named_kms_provider_copy(const mc_named_kms_provider_t *nkp) {
    if (!nkp) {
        return NULL;
    }

    mc_named_kms_provider_t *nkp_copy = bson_malloc0(sizeof(mc_named_kms_provider_t));

    nkp_copy->type = nkp->type;
    nkp_copy->key = bson_strdup(nkp->key);

    switch (nkp->type) {
    case MONGOCRYPT_KMS_PROVIDER_NONE: break;
    case MONGOCRYPT_KMS_PROVIDER_AWS:
        nkp_copy->value.aws.secret_access_key = bson_strdup(nkp->value.aws.secret_access_key);
        nkp_copy->value.aws.access_key_id = bson_strdup(nkp->value.aws.access_key_id);
        nkp_copy->value.aws.session_token = bson_strdup(nkp->value.aws.session_token);
        break;
    case MONGOCRYPT_KMS_PROVIDER_AZURE:
        nkp_copy->value.azure.tenant_id = bson_strdup(nkp->value.azure.tenant_id);
        nkp_copy->value.azure.client_id = bson_strdup(nkp->value.azure.client_id);
        nkp_copy->value.azure.client_secret = bson_strdup(nkp->value.azure.client_secret);
        nkp_copy->value.azure.identity_platform_endpoint =
            _mongocrypt_endpoint_copy(nkp->value.azure.identity_platform_endpoint);
        nkp_copy->value.azure.access_token = bson_strdup(nkp->value.azure.access_token);
        break;
    case MONGOCRYPT_KMS_PROVIDER_GCP:
        nkp_copy->value.gcp.email = bson_strdup(nkp->value.gcp.email);
        _mongocrypt_buffer_copy_to(&nkp->value.gcp.private_key, &nkp_copy->value.gcp.private_key);
        nkp_copy->value.gcp.endpoint = _mongocrypt_endpoint_copy(nkp->value.gcp.endpoint);
        nkp_copy->value.gcp.access_token = bson_strdup(nkp->value.gcp.access_token);
        break;
    case MONGOCRYPT_KMS_PROVIDER_KMIP:
        nkp_copy->value.kmip.endpoint = _mongocrypt_endpoint_copy(nkp->value.kmip.endpoint);
        break;
    case MONGOCRYPT_KMS_PROVIDER_LOCAL:
        _mongocrypt_buffer_copy_to(&nkp->value.local.key, &nkp_copy->value.local.key);
        break;
    }
    return nkp_copy;
}

void mc_named_kms_provider_destroy(mc_named_kms_provider_t *nkp) {
    if (!nkp) {
        return;
    }

    switch (nkp->type) {
    case MONGOCRYPT_KMS_PROVIDER_NONE: break;
    case MONGOCRYPT_KMS_PROVIDER_AWS:
        bson_free(nkp->value.aws.secret_access_key);
        bson_free(nkp->value.aws.access_key_id);
        bson_free(nkp->value.aws.session_token);
        break;
    case MONGOCRYPT_KMS_PROVIDER_AZURE:
        bson_free(nkp->value.azure.tenant_id);
        bson_free(nkp->value.azure.client_id);
        bson_free(nkp->value.azure.client_secret);
        _mongocrypt_endpoint_destroy(nkp->value.azure.identity_platform_endpoint);
        bson_free(nkp->value.azure.access_token);
        break;
    case MONGOCRYPT_KMS_PROVIDER_GCP:
        bson_free(nkp->value.gcp.email);
        _mongocrypt_buffer_cleanup(&nkp->value.gcp.private_key);
        _mongocrypt_endpoint_destroy(nkp->value.gcp.endpoint);
        bson_free(nkp->value.gcp.access_token);
        break;
    case MONGOCRYPT_KMS_PROVIDER_KMIP: _mongocrypt_endpoint_destroy(nkp->value.kmip.endpoint); break;
    case MONGOCRYPT_KMS_PROVIDER_LOCAL: _mongocrypt_buffer_cleanup(&nkp->value.local.key); break;
    }

    bson_free(nkp->key);
    bson_free(nkp);
}

#include "mc-array-private.h"

struct _mc_named_kms_provider_map_t {
    mc_array_t entries;
};

mc_named_kms_provider_map_t *mc_named_kms_provider_map_new(void) {
    mc_named_kms_provider_map_t *nkpm = bson_malloc0(sizeof(mc_named_kms_provider_map_t));
    _mc_array_init(&nkpm->entries, sizeof(mc_named_kms_provider_t *));
    return nkpm;
}

void mc_named_kms_provider_map_destroy(mc_named_kms_provider_map_t *nkpm) {
    if (!nkpm) {
        return;
    }
    for (size_t i = 0; i < nkpm->entries.len; i++) {
        mc_named_kms_provider_t *nkp = _mc_array_index(&nkpm->entries, mc_named_kms_provider_t *, i);
        mc_named_kms_provider_destroy(nkp);
    }
    _mc_array_destroy(&nkpm->entries);
    bson_free(nkpm);
}

bool mc_named_kms_provider_map_has(mc_named_kms_provider_map_t *nkpm, const char *key) {
    BSON_ASSERT_PARAM(nkpm);
    BSON_ASSERT_PARAM(key);
    for (size_t i = 0; i < nkpm->entries.len; i++) {
        mc_named_kms_provider_t *nkp = _mc_array_index(&nkpm->entries, mc_named_kms_provider_t *, i);
        if (0 == strcmp(nkp->key, key)) {
            return true;
        }
    }
    return false;
}

// `mongocrypt_named_kms_provider_map_get` returns NULL if `key` is not in the map.
const mc_named_kms_provider_t *mc_named_kms_provider_map_get(mc_named_kms_provider_map_t *nkpm, const char *key) {
    BSON_ASSERT_PARAM(nkpm);
    BSON_ASSERT_PARAM(key);
    for (size_t i = 0; i < nkpm->entries.len; i++) {
        mc_named_kms_provider_t *nkp = _mc_array_index(&nkpm->entries, mc_named_kms_provider_t *, i);
        if (0 == strcmp(nkp->key, key)) {
            return nkp;
        }
    }
    return NULL;
}

// `mongocrypt_named_kms_provider_map_put` requires the KMS provider name must not be present in the map.
void mc_named_kms_provider_map_put(mc_named_kms_provider_map_t *nkpm, const mc_named_kms_provider_t *new_nkp) {
    BSON_ASSERT_PARAM(nkpm);
    BSON_ASSERT_PARAM(new_nkp);
    mc_named_kms_provider_t *to_put = mc_named_kms_provider_copy(new_nkp);

    // Check if there is an existing entry.
    for (size_t i = 0; i < nkpm->entries.len; i++) {
        mc_named_kms_provider_t *nkp = _mc_array_index(&nkpm->entries, mc_named_kms_provider_t *, i);
        if (0 == strcmp(nkp->key, new_nkp->key)) {
            // Overwrite.
            mc_named_kms_provider_destroy(nkp);
            _mc_array_index(&nkpm->entries, mc_named_kms_provider_t *, i) = to_put;
            return;
        }
    }
    _mc_array_append_val(&nkpm->entries, to_put);
}

bool mc_named_kms_provider_map_is_empty(const mc_named_kms_provider_map_t *nkpm) {
    return nkpm->entries.len == 0;
}

#undef KEY_HELP
