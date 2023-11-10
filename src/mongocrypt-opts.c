/*
 * Copyright 2018-present MongoDB, Inc.
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

#include <bson/bson.h>

#include "mongocrypt-log-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-private.h"

#include <kms_message/kms_b64.h>

void _mongocrypt_opts_init(_mongocrypt_opts_t *opts) {
    BSON_ASSERT_PARAM(opts);
    memset(opts, 0, sizeof(*opts));
}

static void _mongocrypt_opts_kms_provider_azure_cleanup(_mongocrypt_opts_kms_provider_azure_t *kms_provider_azure) {
    if (!kms_provider_azure) {
        return;
    }
    bson_free(kms_provider_azure->client_id);
    bson_free(kms_provider_azure->client_secret);
    bson_free(kms_provider_azure->tenant_id);
    bson_free(kms_provider_azure->access_token);
    _mongocrypt_endpoint_destroy(kms_provider_azure->identity_platform_endpoint);
}

static void _mongocrypt_opts_kms_provider_gcp_cleanup(_mongocrypt_opts_kms_provider_gcp_t *kms_provider_gcp) {
    if (!kms_provider_gcp) {
        return;
    }
    bson_free(kms_provider_gcp->email);
    _mongocrypt_endpoint_destroy(kms_provider_gcp->endpoint);
    _mongocrypt_buffer_cleanup(&kms_provider_gcp->private_key);
    bson_free(kms_provider_gcp->access_token);
}

void _mongocrypt_opts_kms_providers_cleanup(_mongocrypt_opts_kms_providers_t *kms_providers) {
    if (!kms_providers) {
        return;
    }
    bson_free(kms_providers->aws.secret_access_key);
    bson_free(kms_providers->aws.access_key_id);
    bson_free(kms_providers->aws.session_token);
    _mongocrypt_buffer_cleanup(&kms_providers->local.key);
    _mongocrypt_opts_kms_provider_azure_cleanup(&kms_providers->azure);
    _mongocrypt_opts_kms_provider_gcp_cleanup(&kms_providers->gcp);
    _mongocrypt_endpoint_destroy(kms_providers->kmip.endpoint);
}

void _mongocrypt_opts_merge_kms_providers(_mongocrypt_opts_kms_providers_t *dest,
                                          const _mongocrypt_opts_kms_providers_t *source) {
    BSON_ASSERT_PARAM(dest);
    BSON_ASSERT_PARAM(source);

    if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_AWS) {
        memcpy(&dest->aws, &source->aws, sizeof(source->aws));
        dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_AWS;
    }
    if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_LOCAL) {
        memcpy(&dest->local, &source->local, sizeof(source->local));
        dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_LOCAL;
    }
    if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_AZURE) {
        memcpy(&dest->azure, &source->azure, sizeof(source->azure));
        dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_AZURE;
    }
    if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_GCP) {
        memcpy(&dest->gcp, &source->gcp, sizeof(source->gcp));
        dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_GCP;
    }
    if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_KMIP) {
        memcpy(&dest->kmip, &source->kmip, sizeof(source->kmip));
        dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_KMIP;
    }
    /* ensure all providers were copied */
    BSON_ASSERT(!(source->configured_providers & ~dest->configured_providers));
}

void _mongocrypt_opts_cleanup(_mongocrypt_opts_t *opts) {
    if (!opts) {
        return;
    }
    _mongocrypt_opts_kms_providers_cleanup(&opts->kms_providers);
    _mongocrypt_buffer_cleanup(&opts->schema_map);
    _mongocrypt_buffer_cleanup(&opts->encrypted_field_config_map);
    // Free any lib search paths added by the caller
    for (int i = 0; i < opts->n_crypt_shared_lib_search_paths; ++i) {
        mstr_free(opts->crypt_shared_lib_search_paths[i]);
    }
    bson_free(opts->crypt_shared_lib_search_paths);
    mstr_free(opts->crypt_shared_lib_override_path);
}

bool _mongocrypt_opts_kms_providers_validate(_mongocrypt_opts_t *opts,
                                             _mongocrypt_opts_kms_providers_t *kms_providers,
                                             mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(opts);
    BSON_ASSERT_PARAM(kms_providers);

    if (!kms_providers->configured_providers && !kms_providers->need_credentials) {
        CLIENT_ERR("no kms provider set");
        return false;
    }

    if (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_AWS) {
        if (!kms_providers->aws.access_key_id || !kms_providers->aws.secret_access_key) {
            CLIENT_ERR("aws credentials unset");
            return false;
        }
    }

    if (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_LOCAL) {
        if (_mongocrypt_buffer_empty(&kms_providers->local.key)) {
            CLIENT_ERR("local data key unset");
            return false;
        }
    }

    if (kms_providers->need_credentials && !opts->use_need_kms_credentials_state) {
        CLIENT_ERR("on-demand credentials not enabled");
        return false;
    }

    return true;
}

/* _shares_bson_fields checks if @one or @two share any top-level field names.
 * Returns false on error and sets @status. Returns true if no error
 * occurred. Sets @found to the first shared field name found.
 * If no shared field names are found, @found is set to NULL.
 */
static bool _shares_bson_fields(bson_t *one, bson_t *two, const char **found, mongocrypt_status_t *status) {
    bson_iter_t iter1;
    bson_iter_t iter2;

    BSON_ASSERT_PARAM(one);
    BSON_ASSERT_PARAM(two);
    BSON_ASSERT_PARAM(found);
    *found = NULL;
    if (!bson_iter_init(&iter1, one)) {
        CLIENT_ERR("error iterating one BSON in _shares_bson_fields");
        return false;
    }
    while (bson_iter_next(&iter1)) {
        const char *key1 = bson_iter_key(&iter1);

        if (!bson_iter_init(&iter2, two)) {
            CLIENT_ERR("error iterating two BSON in _shares_bson_fields");
            return false;
        }
        while (bson_iter_next(&iter2)) {
            const char *key2 = bson_iter_key(&iter2);
            if (0 == strcmp(key1, key2)) {
                *found = key1;
                return true;
            }
        }
    }
    return true;
}

/* _validate_encrypted_field_config_map_and_schema_map validates that the same
 * namespace is not both in encrypted_field_config_map and schema_map. */
static bool _validate_encrypted_field_config_map_and_schema_map(_mongocrypt_buffer_t *encrypted_field_config_map,
                                                                _mongocrypt_buffer_t *schema_map,
                                                                mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(encrypted_field_config_map);
    BSON_ASSERT_PARAM(schema_map);

    const char *found;
    bson_t schema_map_bson;
    bson_t encrypted_field_config_map_bson;

    /* If either map is unset, there is nothing to validate. Return true to
     * signal no error. */
    if (_mongocrypt_buffer_empty(encrypted_field_config_map)) {
        return true;
    }
    if (_mongocrypt_buffer_empty(schema_map)) {
        return true;
    }

    if (!_mongocrypt_buffer_to_bson(schema_map, &schema_map_bson)) {
        CLIENT_ERR("error converting schema_map to BSON");
        return false;
    }
    if (!_mongocrypt_buffer_to_bson(encrypted_field_config_map, &encrypted_field_config_map_bson)) {
        CLIENT_ERR("error converting encrypted_field_config_map to BSON");
        return false;
    }
    if (!_shares_bson_fields(&schema_map_bson, &encrypted_field_config_map_bson, &found, status)) {
        return false;
    }
    if (found != NULL) {
        CLIENT_ERR("%s is present in both schema_map and encrypted_field_config_map", found);
        return false;
    }
    return true;
}

bool _mongocrypt_opts_validate(_mongocrypt_opts_t *opts, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(opts);

    if (!_validate_encrypted_field_config_map_and_schema_map(&opts->encrypted_field_config_map,
                                                             &opts->schema_map,
                                                             status)) {
        return false;
    }
    return _mongocrypt_opts_kms_providers_validate(opts, &opts->kms_providers, status);
}

bool _mongocrypt_parse_optional_utf8(const bson_t *bson, const char *dotkey, char **out, mongocrypt_status_t *status) {
    bson_iter_t iter;
    bson_iter_t child;

    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    *out = NULL;

    if (!bson_iter_init(&iter, bson)) {
        CLIENT_ERR("invalid BSON");
        return false;
    }
    if (!bson_iter_find_descendant(&iter, dotkey, &child)) {
        /* Not found. Not an error. */
        return true;
    }
    if (!BSON_ITER_HOLDS_UTF8(&child)) {
        CLIENT_ERR("expected UTF-8 %s", dotkey);
        return false;
    }

    *out = bson_strdup(bson_iter_utf8(&child, NULL));
    return true;
}

bool _mongocrypt_parse_required_utf8(const bson_t *bson, const char *dotkey, char **out, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    if (!_mongocrypt_parse_optional_utf8(bson, dotkey, out, status)) {
        return false;
    }

    if (!*out) {
        CLIENT_ERR("expected UTF-8 %s", dotkey);
        return false;
    }

    return true;
}

bool _mongocrypt_parse_optional_endpoint(const bson_t *bson,
                                         const char *dotkey,
                                         _mongocrypt_endpoint_t **out,
                                         _mongocrypt_endpoint_parse_opts_t *opts,
                                         mongocrypt_status_t *status) {
    char *endpoint_raw;

    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    *out = NULL;

    if (!_mongocrypt_parse_optional_utf8(bson, dotkey, &endpoint_raw, status)) {
        return false;
    }

    /* Not found. Not an error. */
    if (!endpoint_raw) {
        return true;
    }

    *out = _mongocrypt_endpoint_new(endpoint_raw, -1, opts, status);
    bson_free(endpoint_raw);
    return (*out) != NULL;
}

bool _mongocrypt_parse_required_endpoint(const bson_t *bson,
                                         const char *dotkey,
                                         _mongocrypt_endpoint_t **out,
                                         _mongocrypt_endpoint_parse_opts_t *opts,
                                         mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    if (!_mongocrypt_parse_optional_endpoint(bson, dotkey, out, opts, status)) {
        return false;
    }

    if (!*out) {
        CLIENT_ERR("expected endpoint %s", dotkey);
        return false;
    }

    return true;
}

bool _mongocrypt_parse_optional_binary(const bson_t *bson,
                                       const char *dotkey,
                                       _mongocrypt_buffer_t *out,
                                       mongocrypt_status_t *status) {
    bson_iter_t iter;
    bson_iter_t child;

    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    _mongocrypt_buffer_init(out);

    if (!bson_iter_init(&iter, bson)) {
        CLIENT_ERR("invalid BSON");
        return false;
    }
    if (!bson_iter_find_descendant(&iter, dotkey, &child)) {
        /* Not found. Not an error. */
        return true;
    }
    if (BSON_ITER_HOLDS_UTF8(&child)) {
        size_t out_len;
        /* Attempt to base64 decode. */
        out->data = kms_message_b64_to_raw(bson_iter_utf8(&child, NULL), &out_len);
        if (!out->data) {
            CLIENT_ERR("unable to parse base64 from UTF-8 field %s", dotkey);
            return false;
        }
        BSON_ASSERT(out_len <= UINT32_MAX);
        out->len = (uint32_t)out_len;
        out->owned = true;
    } else if (BSON_ITER_HOLDS_BINARY(&child)) {
        if (!_mongocrypt_buffer_copy_from_binary_iter(out, &child)) {
            CLIENT_ERR("unable to parse binary from field %s", dotkey);
            return false;
        }
    } else {
        CLIENT_ERR("expected UTF-8 or binary %s", dotkey);
        return false;
    }

    return true;
}

bool _mongocrypt_parse_required_binary(const bson_t *bson,
                                       const char *dotkey,
                                       _mongocrypt_buffer_t *out,
                                       mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    if (!_mongocrypt_parse_optional_binary(bson, dotkey, out, status)) {
        return false;
    }

    if (out->len == 0) {
        CLIENT_ERR("expected UTF-8 or binary %s", dotkey);
        return false;
    }

    return true;
}

bool _mongocrypt_check_allowed_fields_va(const bson_t *bson, const char *dotkey, mongocrypt_status_t *status, ...) {
    va_list args;
    const char *field;
    bson_iter_t iter;

    BSON_ASSERT_PARAM(bson);

    if (dotkey) {
        bson_iter_t parent;

        bson_iter_init(&parent, bson);
        if (!bson_iter_find_descendant(&parent, dotkey, &iter) || !BSON_ITER_HOLDS_DOCUMENT(&iter)) {
            CLIENT_ERR("invalid BSON, expected %s", dotkey);
            return false;
        }
        bson_iter_recurse(&iter, &iter);
    } else {
        bson_iter_init(&iter, bson);
    }

    while (bson_iter_next(&iter)) {
        bool found = false;

        va_start(args, status);
        field = va_arg(args, const char *);
        while (field) {
            if (0 == strcmp(field, bson_iter_key(&iter))) {
                found = true;
                break;
            }
            field = va_arg(args, const char *);
        }
        va_end(args);

        if (!found) {
            CLIENT_ERR("Unexpected field: '%s'", bson_iter_key(&iter));
            return false;
        }
    }
    return true;
}

// `_mongocrypt_named_kms_provider_from_bson` returns NULL on error and sets an error status.
_mongocrypt_named_kms_provider_t *
_mongocrypt_named_kms_provider_new(const char *key, const bson_t *def, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(key);
    BSON_ASSERT_PARAM(def);
    BSON_ASSERT(status || true); // Optional.

    char *prefix = NULL;
    char *name = NULL;
    _mongocrypt_named_kms_provider_t *nkp = bson_malloc0(sizeof(_mongocrypt_named_kms_provider_t));
    bool ok = false;

    nkp->key = bson_strdup(key);

#define KEY_HELP "Must be of form `<provider type>:<name>`. Example: `local:name`."

    // Parse `key` into `prefix` and `name`.
    {
        const char *prefix_end = strstr(key, ":");
        if (prefix_end == NULL) {
            CLIENT_ERR("invalid KMS provider `%s`: missing colon. " KEY_HELP, key);
            goto fail;
        }
        const char *next_colon = strstr(prefix_end + 1, ":");
        if (next_colon != NULL) {
            CLIENT_ERR("invalid KMS provider `%s`: extra colon. " KEY_HELP, key);
            goto fail;
        }

        prefix = bson_strndup(key, prefix_end - key);
        if (0 == strlen(prefix)) {
            CLIENT_ERR("invalid KMS provider `%s`: empty prefix. " KEY_HELP, key);
            goto fail;
        }

        name = bson_strdup(prefix_end + 1);
        if (0 == strlen(name)) {
            CLIENT_ERR("invalid KMS provider `%s`: empty name. " KEY_HELP, key);
            goto fail;
        }
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

#undef KEY_HELP

succeed:
    ok = true;
fail:
    if (!ok) {
        _mongocrypt_named_kms_provider_destroy(nkp);
        nkp = NULL;
    }
    bson_free(name);
    bson_free(prefix);
    return nkp;
}

_mongocrypt_named_kms_provider_t *_mongocrypt_named_kms_provider_copy(const _mongocrypt_named_kms_provider_t *nkp) {
    if (!nkp) {
        return NULL;
    }

    _mongocrypt_named_kms_provider_t *nkp_copy = bson_malloc0(sizeof(_mongocrypt_named_kms_provider_t));

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

void _mongocrypt_named_kms_provider_destroy(_mongocrypt_named_kms_provider_t *nkp) {
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

struct __mongocrypt_named_kms_provider_map_t {
    mc_array_t entries;
};

_mongocrypt_named_kms_provider_map_t *_mongocrypt_named_kms_provider_map_new(void) {
    _mongocrypt_named_kms_provider_map_t *nkpm = bson_malloc0(sizeof(_mongocrypt_named_kms_provider_map_t));
    _mc_array_init(&nkpm->entries, sizeof(_mongocrypt_named_kms_provider_t *));
    return nkpm;
}

void _mongocrypt_named_kms_provider_map_destroy(_mongocrypt_named_kms_provider_map_t *nkpm) {
    if (!nkpm) {
        return;
    }
    for (size_t i = 0; i < nkpm->entries.len; i++) {
        _mongocrypt_named_kms_provider_t *nkp = _mc_array_index(&nkpm->entries, _mongocrypt_named_kms_provider_t *, i);
        _mongocrypt_named_kms_provider_destroy(nkp);
    }
    _mc_array_destroy(&nkpm->entries);
    bson_free(nkpm);
}

bool _mongocrypt_named_kms_provider_map_has(_mongocrypt_named_kms_provider_map_t *nkpm, const char *key) {
    BSON_ASSERT_PARAM(nkpm);
    BSON_ASSERT_PARAM(key);
    for (size_t i = 0; i < nkpm->entries.len; i++) {
        _mongocrypt_named_kms_provider_t *nkp = _mc_array_index(&nkpm->entries, _mongocrypt_named_kms_provider_t *, i);
        if (0 == strcmp(nkp->key, key)) {
            return true;
        }
    }
    return false;
}

// `mongocrypt_named_kms_provider_map_get` returns NULL if `key` is not in the map.
const _mongocrypt_named_kms_provider_t *
_mongocrypt_named_kms_provider_map_get(_mongocrypt_named_kms_provider_map_t *nkpm, const char *key) {
    BSON_ASSERT_PARAM(nkpm);
    BSON_ASSERT_PARAM(key);
    for (size_t i = 0; i < nkpm->entries.len; i++) {
        _mongocrypt_named_kms_provider_t *nkp = _mc_array_index(&nkpm->entries, _mongocrypt_named_kms_provider_t *, i);
        if (0 == strcmp(nkp->key, key)) {
            return nkp;
        }
    }
    return NULL;
}

// `mongocrypt_named_kms_provider_map_put` requires the KMS provider name must not be present in the map.
void _mongocrypt_named_kms_provider_map_put(_mongocrypt_named_kms_provider_map_t *nkpm,
                                            const _mongocrypt_named_kms_provider_t *new_nkp) {
    BSON_ASSERT_PARAM(nkpm);
    BSON_ASSERT_PARAM(new_nkp);
    _mongocrypt_named_kms_provider_t *to_put = _mongocrypt_named_kms_provider_copy(new_nkp);

    // Check if there is an existing entry.
    for (size_t i = 0; i < nkpm->entries.len; i++) {
        _mongocrypt_named_kms_provider_t *nkp = _mc_array_index(&nkpm->entries, _mongocrypt_named_kms_provider_t *, i);
        if (0 == strcmp(nkp->key, new_nkp->key)) {
            // Overwrite.
            _mongocrypt_named_kms_provider_destroy(nkp);
            _mc_array_index(&nkpm->entries, _mongocrypt_named_kms_provider_t *, i) = to_put;
            return;
        }
    }
    _mc_array_append_val(&nkpm->entries, to_put);
}
