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

#include <mongocrypt-opts-private.h>

#include <kms_message/kms_b64.h> // kms_message_b64_pton
#include <mongocrypt-cache-oauth-private.h>
#include <test-mongocrypt-assert-match-bson.h>
#include <test-mongocrypt.h>

#define LOCAL_KEK1_BASE64                                                                                              \
    "+ol0TFyLuVvKFSqGzOFGuaOGQnnyfAqalhOv3II/VSxQTCORCGhOmw/IxhthGx0r"                                                 \
    "2R/NpMWc91qQ8Ieho4QuE9ucToTnpJ4OquFpdZv2IcO4gey3ecZGCl9jPDig8F+a"

#define LOCAL_KEK2_BASE64                                                                                              \
    "yPSpsO8FoVkmt+qdTDnw/pJaKriwfI6NLD1yse3BZLd3ZcXb3rAVJEA+/yu/vPzE"                                                 \
    "8ju7OYTV63AwfLor8Hg9qzo8lyYC6H3RSfdJ9g9aXdCRfGZJgpbpchJUjR06JMLR"

#define BSON_STR(...) #__VA_ARGS__

extern auth_request_t *auth_request_new();
extern mc_named_kms_provider_auth_request_map_t *mc_named_kms_provider_auth_request_map_new(void);
extern void mc_named_kms_provider_auth_request_map_destroy(mc_named_kms_provider_auth_request_map_t *nkparm);
extern auth_request_t *mc_named_kms_provider_auth_request_map_get_mut(mc_named_kms_provider_auth_request_map_t *nkparm,
                                                                      const char *kms_id);
extern void mc_named_kms_provider_auth_request_map_put(mc_named_kms_provider_auth_request_map_t *nkparm,
                                                       auth_request_t *ar);

static void test_mc_named_kms_provider_auth_request_map(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();
    mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
        "azure:2" : {
            "tenantId" : "placeholder-tenantId",
            "clientId" : "placeholder-clientId",
            "clientSecret" : "placeholder-clientSecret",
            "identityPlatformEndpoint" : "placeholder-identityPlatformEndpoint.com"
        }
    }));
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);

    mongocrypt_status_t *status = mongocrypt_status_new();

    // Test inserting one entry.
    {
        auth_request_t *ar;
        // Create auth request.
        {
            ar = auth_request_new();
            _mongocrypt_endpoint_t *endpoint =
                _mongocrypt_endpoint_new("placeholder-keyVaultEndpoint.com", -1, NULL /* opts */, status);
            ASSERT_OK_STATUS(endpoint, status);
            ASSERT_OK(_mongocrypt_kms_ctx_init_azure_auth(&ar->kms,
                                                          &crypt->log,
                                                          &crypt->opts.kms_providers,
                                                          crypt->opts.nkpm,
                                                          "azure:2",
                                                          endpoint),
                      &ar->kms);
            ar->initialized = true;
            _mongocrypt_endpoint_destroy(endpoint);
        }

        mc_named_kms_provider_auth_request_map_t *nkparm = mc_named_kms_provider_auth_request_map_new();
        mc_named_kms_provider_auth_request_map_put(nkparm, ar);
        auth_request_t *got = mc_named_kms_provider_auth_request_map_get_mut(nkparm, "azure:2");

        ASSERT(got);
        ASSERT(got->initialized);

        mc_named_kms_provider_auth_request_map_destroy(nkparm);
    }

    mongocrypt_status_destroy(status);
    mongocrypt_destroy(crypt);
}

static void test_mc_named_kms_provider_oauth_map(_mongocrypt_tester_t *tester) {
    // Create an unused `mongocrypt_t` to initialize library with `_mongocrypt_do_init`. Otherwise, parsing base64 may
    // fail.
    {
        mongocrypt_t *unused = mongocrypt_new();
        mongocrypt_destroy(unused);
    }

    mongocrypt_status_t *status = mongocrypt_status_new();
    bson_t *response1 = TMP_BSON(BSON_STR({"access_token" : "foo", "expires_in" : 1234}));
    bson_t *response2 = TMP_BSON(BSON_STR({"access_token" : "bar", "expires_in" : 4567}));

    // Test inserting one entry.
    {
        mc_named_kms_provider_oauth_map_t *nkpmo = mc_named_kms_provider_oauth_map_new();
        ASSERT(NULL == mc_named_kms_provider_oauth_map_get_token(nkpmo, "local:1"));
        ASSERT_OK_STATUS(mc_named_kms_provider_oauth_map_add_response(nkpmo, "local:1", response1, status), status);
        char *got = mc_named_kms_provider_oauth_map_get_token(nkpmo, "local:1");
        ASSERT_STREQUAL(got, "foo");
        bson_free(got);
        mc_named_kms_provider_oauth_map_destroy(nkpmo);
    }

    // Test inserting two entries.
    {
        mc_named_kms_provider_oauth_map_t *nkpmo = mc_named_kms_provider_oauth_map_new();

        // Insert first.
        {
            ASSERT(NULL == mc_named_kms_provider_oauth_map_get_token(nkpmo, "local:1"));
            ASSERT_OK_STATUS(mc_named_kms_provider_oauth_map_add_response(nkpmo, "local:1", response1, status), status);
            char *got = mc_named_kms_provider_oauth_map_get_token(nkpmo, "local:1");
            ASSERT_STREQUAL(got, "foo");
            bson_free(got);
        }

        // Insert second.
        {
            ASSERT(NULL == mc_named_kms_provider_oauth_map_get_token(nkpmo, "local:2"));
            ASSERT_OK_STATUS(mc_named_kms_provider_oauth_map_add_response(nkpmo, "local:2", response2, status), status);
            char *got = mc_named_kms_provider_oauth_map_get_token(nkpmo, "local:2");
            ASSERT_STREQUAL(got, "bar");
            bson_free(got);
        }

        mc_named_kms_provider_oauth_map_destroy(nkpmo);
    }

    // Test overwriting an entry.
    {
        mc_named_kms_provider_oauth_map_t *nkpmo = mc_named_kms_provider_oauth_map_new();

        // Insert first.
        {
            ASSERT(NULL == mc_named_kms_provider_oauth_map_get_token(nkpmo, "local:1"));
            ASSERT_OK_STATUS(mc_named_kms_provider_oauth_map_add_response(nkpmo, "local:1", response1, status), status);
            char *got = mc_named_kms_provider_oauth_map_get_token(nkpmo, "local:1");
            ASSERT_STREQUAL(got, "foo");
            bson_free(got);
        }

        // Overwrite 'local:1' with a different token.
        {
            ASSERT_OK_STATUS(mc_named_kms_provider_oauth_map_add_response(nkpmo, "local:1", response2, status), status);
            char *got = mc_named_kms_provider_oauth_map_get_token(nkpmo, "local:1");
            ASSERT_STREQUAL(got, "bar");
            bson_free(got);
        }

        mc_named_kms_provider_oauth_map_destroy(nkpmo);
    }
    // Test getting a missing entry.
    {
        mc_named_kms_provider_oauth_map_t *nkpmo = mc_named_kms_provider_oauth_map_new();
        ASSERT(NULL == mc_named_kms_provider_oauth_map_get_token(nkpmo, "local:1"));
        mc_named_kms_provider_oauth_map_destroy(nkpmo);
    }

    mongocrypt_status_destroy(status);
}

static void test_rewrap_with_named_kms_provider_for_local(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();
    mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local" : {"key" : "%s"}, "local:2" : {"key" : "%s"}}),
                                                   LOCAL_KEK1_BASE64,
                                                   LOCAL_KEK2_BASE64);

    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);

    // Create DEK.
    _mongocrypt_buffer_t dek;
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        _mongocrypt_buffer_copy_from_binary(&dek, bin);
        bson_t dek_bson;
        ASSERT(_mongocrypt_buffer_to_bson(&dek, &dek_bson));
        _assert_match_bson(&dek_bson, TMP_BSON(BSON_STR({"masterKey" : {"provider" : "local"}})));
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    // Test rewrapping from unnamed KMS to named KMS.
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:2"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_rewrap_many_datakey_init(ctx, TEST_BSON("{}")), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        _mongocrypt_buffer_t dek_rewrapped;
        _mongocrypt_buffer_copy_from_binary(&dek_rewrapped, bin);
        _mongocrypt_buffer_cleanup(&dek_rewrapped);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    _mongocrypt_buffer_cleanup(&dek);
    mongocrypt_destroy(crypt);
}

static void test_explicit_with_named_kms_provider_for_azure(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();
    mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
        "azure:2" : {
            "tenantId" : "placeholder-tenantId",
            "clientId" : "placeholder-clientId",
            "clientSecret" : "placeholder-clientSecret",
            "identityPlatformEndpoint" : "placeholder-identityPlatformEndpoint.com"
        }
    }));
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);

    // Create DEK.
    _mongocrypt_buffer_t dek;
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                               "provider" : "azure:2",
                                                               "keyName" : "placeholder-keyName",
                                                               "keyVaultEndpoint" : "placeholder-keyVaultEndpoint.com"
                                                           }))),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "azure2"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to encrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/encrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        _mongocrypt_buffer_copy_from_binary(&dek, bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    // Test encrypting without cached DEK.
    {
        // Recreate the `mongocrypt_t`.
        mongocrypt_destroy(crypt);
        crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "azure2"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
        ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to decrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/decrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    // Test encrypting with cached DEK. Store result for later decryption.
    _mongocrypt_buffer_t ciphertext;
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "azure2"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
        ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);
        // DEK is already cached. State transitions directly to ready.
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        _mongocrypt_buffer_copy_from_binary(&ciphertext, bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    // Test decrypting with cached DEK.
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);
        // DEK is already cached. State transitions directly to ready.
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    // Test decrypting without cached DEK.
    {
        // Recreate the `mongocrypt_t`.
        mongocrypt_destroy(crypt);
        crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Decrypt.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to decrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/decrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    // Test decrypting with a cached oauth token, but not a cached DEK.
    {
        // Recreate the `mongocrypt_t`.
        mongocrypt_destroy(crypt);
        crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Decrypt.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Recreate the `mongocrypt_ctx_t`. Expect the oauth token to be cached but the DEK not to be cached.
        mongocrypt_ctx_destroy(ctx);

        ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);

        // Needs KMS to decrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/decrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    _mongocrypt_buffer_cleanup(&ciphertext);
    _mongocrypt_buffer_cleanup(&dek);
    mongocrypt_destroy(crypt);
}

static void test_explicit_with_named_kms_provider_for_local(_mongocrypt_tester_t *tester) {
    mongocrypt_t *crypt = mongocrypt_new();
    mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:2" : {"key" : "%s"}}), LOCAL_KEK2_BASE64);

    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);

    // Create DEK.
    _mongocrypt_buffer_t dek;
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:2"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "local2"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        _mongocrypt_buffer_copy_from_binary(&dek, bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    // Test encrypting.
    _mongocrypt_buffer_t ciphertext;
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_alt_name(ctx, TEST_BSON(BSON_STR({"keyAltName" : "local2"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_setopt_algorithm(ctx, MONGOCRYPT_ALGORITHM_DETERMINISTIC_STR, -1), ctx);
        ASSERT_OK(mongocrypt_ctx_explicit_encrypt_init(ctx, TEST_BSON(BSON_STR({"v" : "foo"}))), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        _mongocrypt_buffer_copy_from_binary(&ciphertext, bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    // Test decrypting with cached DEK.
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);
        // Key is already cached. State transitions directly to ready.
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    // Test decrypting without cached DEK.
    {
        // Recreating the `mongocrypt_t`.
        mongocrypt_destroy(crypt);
        crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Decrypt.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_explicit_decrypt_init(ctx, _mongocrypt_buffer_as_binary(&ciphertext)), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, _mongocrypt_buffer_as_binary(&dek)), ctx);
        ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *bin = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, bin), ctx);
        ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON(BSON_STR({"v" : "foo"})), bin);
        mongocrypt_binary_destroy(bin);
        mongocrypt_ctx_destroy(ctx);
    }

    _mongocrypt_buffer_cleanup(&ciphertext);
    _mongocrypt_buffer_cleanup(&dek);
    mongocrypt_destroy(crypt);
}

static void test_create_datakey_with_named_kms_provider(_mongocrypt_tester_t *tester) {
    // Test configuring with an unconfigured KMS provider.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:2" : {"key" : "%s"}}), LOCAL_KEK2_BASE64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(
            mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:not_configured"}))),
            ctx);
        ASSERT_FAILS(mongocrypt_ctx_datakey_init(ctx),
                     ctx,
                     "requested named kms provider 'local:not_configured' is not configured");

        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test successfully creating a local DEK with a named KMS provider.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:2" : {"key" : "%s"}}), LOCAL_KEK2_BASE64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({"provider" : "local:2"}))), ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "local:2"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test successfully creating an Azure DEK with a named KMS provider
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({
            "azure:2" : {
                "tenantId" : "placeholder-tenantId",
                "clientId" : "placeholder-clientId",
                "clientSecret" : "placeholder-clientSecret",
                "identityPlatformEndpoint" : "placeholder-identityPlatformEndpoint.com"
            }
        }));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                               "provider" : "azure:2",
                                                               "keyName" : "placeholder-keyName",
                                                               "keyVaultEndpoint" : "placeholder-keyVaultEndpoint.com"
                                                           }))),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        // Needs KMS for oauth token.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-identityPlatformEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/oauth-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        // Needs KMS to encrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/encrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "azure:2"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }

    // Test successfully creating an Azure KEK when `accessToken` is passed.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"azure:2" : {"accessToken" : "foo"}}));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);

        // Create with named KMS provider.
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_setopt_key_encryption_key(ctx, TEST_BSON(BSON_STR({
                                                               "provider" : "azure:2",
                                                               "keyName" : "placeholder-keyName",
                                                               "keyVaultEndpoint" : "placeholder-keyVaultEndpoint.com"
                                                           }))),
                  ctx);
        ASSERT_OK(mongocrypt_ctx_datakey_init(ctx), ctx);

        // Needs KMS to encrypt DEK.
        {
            ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_KMS);
            mongocrypt_kms_ctx_t *kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(kctx);
            const char *endpoint;
            ASSERT_OK(mongocrypt_kms_ctx_endpoint(kctx, &endpoint), kctx);
            ASSERT_STREQUAL(endpoint, "placeholder-keyVaultEndpoint.com:443");
            ASSERT_OK(mongocrypt_kms_ctx_feed(kctx, TEST_FILE("./test/data/azure-auth/encrypt-response.txt")), kctx);
            kctx = mongocrypt_ctx_next_kms_ctx(ctx);
            ASSERT(!kctx);
            ASSERT_OK(mongocrypt_ctx_kms_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        mongocrypt_binary_t *out = mongocrypt_binary_new();
        ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
        // Check that `out` contains name.
        bson_t out_bson;
        ASSERT(_mongocrypt_binary_to_bson(out, &out_bson));
        char *pattern = BSON_STR({"masterKey" : {"provider" : "azure:2"}});
        _assert_match_bson(&out_bson, TMP_BSON(pattern));
        bson_destroy(&out_bson);
        mongocrypt_binary_destroy(out);
        mongocrypt_ctx_destroy(ctx);
        mongocrypt_destroy(crypt);
    }
}

static void test_mongocrypt_kek_parse_with_named_kms_provider(_mongocrypt_tester_t *tester) {
    // Create an unused `mongocrypt_t` to initialize library with `_mongocrypt_do_init`. Otherwise, parsing base64 may
    // fail.
    {
        mongocrypt_t *unused = mongocrypt_new();
        mongocrypt_destroy(unused);
    }

    mongocrypt_status_t *status = mongocrypt_status_new();

    // Can be parsed.
    {
        _mongocrypt_kek_t kek = (_mongocrypt_kek_t){0};
        bool ok = _mongocrypt_kek_parse_owned(TMP_BSON(BSON_STR({"provider" : "local:2"})), &kek, status);
        ASSERT_OK_STATUS(ok, status);
        ASSERT_STREQUAL(kek.kms_id, "local:2");
        ASSERT(kek.is_named);
        _mongocrypt_kek_cleanup(&kek);
    }

    // Can be copied.
    {
        _mongocrypt_kek_t kek = (_mongocrypt_kek_t){0};
        _mongocrypt_kek_t kek_copy = (_mongocrypt_kek_t){0};
        bool ok = _mongocrypt_kek_parse_owned(TMP_BSON(BSON_STR({"provider" : "local:2"})), &kek, status);
        ASSERT_OK_STATUS(ok, status);
        _mongocrypt_kek_copy_to(&kek, &kek_copy);
        ASSERT_STREQUAL(kek_copy.kms_id, "local:2");
        ASSERT(kek_copy.is_named);
        _mongocrypt_kek_cleanup(&kek_copy);
        _mongocrypt_kek_cleanup(&kek);
    }

    // Can be appended.
    {
        bson_t out = BSON_INITIALIZER;
        _mongocrypt_kek_t kek = (_mongocrypt_kek_t){0};
        bool ok = _mongocrypt_kek_parse_owned(TMP_BSON(BSON_STR({"provider" : "local:2"})), &kek, status);
        ASSERT_OK_STATUS(ok, status);
        ASSERT_OK_STATUS(_mongocrypt_kek_append(&kek, &out, status), status);
        bson_destroy(&out);
        _assert_match_bson(&out, TMP_BSON(BSON_STR({"provider" : "local:2"})));
        _mongocrypt_kek_cleanup(&kek);
    }

    mongocrypt_status_destroy(status);
}

static void test_configuring_named_kms_providers(_mongocrypt_tester_t *tester) {
    // Test that a named KMS provider can be set.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local" : {"key" : "%s"}, "local:2" : {"key" : "%s"}}),
                                                       LOCAL_KEK1_BASE64,
                                                       LOCAL_KEK2_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(ok, crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Test that an unrecognized named KMS provider errors.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"foo:bar" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_FAILS(ok, crypt, "invalid KMS provider");
        mongocrypt_destroy(crypt);
    }

    // Test that only configuring named KMS provider is OK.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:1" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(ok, crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Test character validation. Only valid characters are: [a-zA-Z0-9_]
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers =
            TEST_BSON(BSON_STR({"local:name_with_invalid_character_?" : {"key" : "%s"}}), LOCAL_KEK1_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_FAILS(ok, crypt, "unsupported character `?`");
        mongocrypt_destroy(crypt);
    }

    // Test configuring a named KMS provider with an empty document is prohibited.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local:2" : {}}));
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_FAILS(ok, crypt, "expected UTF-8 or binary key");
        mongocrypt_destroy(crypt);

        // An empty document is allowed for a non-named KMS provider to configure on-demand credentials.
        crypt = mongocrypt_new();
        kms_providers = TEST_BSON(BSON_STR({"local" : {}}));
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        mongocrypt_destroy(crypt);
    }
}

static void test_mc_named_kms_provider_map(_mongocrypt_tester_t *tester) {
    // Create an unused `mongocrypt_t` to initialize library with `_mongocrypt_do_init`. Otherwise, parsing base64 may
    // fail.
    {
        mongocrypt_t *unused = mongocrypt_new();
        mongocrypt_destroy(unused);
    }

    mongocrypt_status_t *status = mongocrypt_status_new();

    mc_named_kms_provider_t *nkp1, *nkp2;
    // Create two named KMS providers to use in tests.
    {
        nkp1 = mc_named_kms_provider_new("local:1", TMP_BSON(BSON_STR({"key" : "%s"}), LOCAL_KEK1_BASE64), status);
        ASSERT_OK_STATUS(nkp1 != NULL, status);
        nkp2 = mc_named_kms_provider_new("local:2", TMP_BSON(BSON_STR({"key" : "%s"}), LOCAL_KEK2_BASE64), status);
        ASSERT_OK_STATUS(nkp2 != NULL, status);
    }

    _mongocrypt_buffer_t kek1_buf, kek2_buf;
    // Create buffers for KEK1 and KEK2 to assert expected data in tests.
    {
        _mongocrypt_buffer_init(&kek1_buf);
        _mongocrypt_buffer_resize(&kek1_buf, MONGOCRYPT_KEY_LEN);
        int result_len = kms_message_b64_pton(LOCAL_KEK1_BASE64, kek1_buf.data, (size_t)kek1_buf.len);
        ASSERT_CMPINT(result_len, ==, MONGOCRYPT_KEY_LEN);

        _mongocrypt_buffer_init(&kek2_buf);
        _mongocrypt_buffer_resize(&kek2_buf, MONGOCRYPT_KEY_LEN);
        result_len = kms_message_b64_pton(LOCAL_KEK2_BASE64, kek2_buf.data, (size_t)kek2_buf.len);
        ASSERT_CMPINT(result_len, ==, MONGOCRYPT_KEY_LEN);
    }

    // Test inserting one entry.
    {
        mc_named_kms_provider_map_t *nkpm = mc_named_kms_provider_map_new();
        ASSERT(!mc_named_kms_provider_map_has(nkpm, "local:1"));
        mc_named_kms_provider_map_put(nkpm, nkp1);
        ASSERT(mc_named_kms_provider_map_has(nkpm, "local:1"));
        const mc_named_kms_provider_t *got = mc_named_kms_provider_map_get(nkpm, "local:1");
        ASSERT(got);
        ASSERT_STREQUAL(got->kms_id, "local:1");
        ASSERT(got->type == MONGOCRYPT_KMS_PROVIDER_LOCAL);
        ASSERT_CMPBUF(kek1_buf, got->value.local.key);
        mc_named_kms_provider_map_destroy(nkpm);
    }

    // Test inserting two entries.
    {
        mc_named_kms_provider_map_t *nkpm = mc_named_kms_provider_map_new();
        // Insert first.
        {
            ASSERT(!mc_named_kms_provider_map_has(nkpm, "local:1"));
            mc_named_kms_provider_map_put(nkpm, nkp1);
            ASSERT(mc_named_kms_provider_map_has(nkpm, "local:1"));
            const mc_named_kms_provider_t *got = mc_named_kms_provider_map_get(nkpm, "local:1");
            ASSERT(got);
            ASSERT_STREQUAL(got->kms_id, "local:1");
            ASSERT(got->type == MONGOCRYPT_KMS_PROVIDER_LOCAL);
            ASSERT_CMPBUF(kek1_buf, got->value.local.key);
        }

        // Insert second.
        {
            ASSERT(!mc_named_kms_provider_map_has(nkpm, "local:2"));
            mc_named_kms_provider_map_put(nkpm, nkp2);
            ASSERT(mc_named_kms_provider_map_has(nkpm, "local:2"));
            const mc_named_kms_provider_t *got = mc_named_kms_provider_map_get(nkpm, "local:2");
            ASSERT(got);
            ASSERT_STREQUAL(got->kms_id, "local:2");
            ASSERT(got->type == MONGOCRYPT_KMS_PROVIDER_LOCAL);
            ASSERT_CMPBUF(kek2_buf, got->value.local.key);
        }
        mc_named_kms_provider_map_destroy(nkpm);
    }

    // Test overwriting an entry.
    {
        mc_named_kms_provider_map_t *nkpm = mc_named_kms_provider_map_new();
        // Insert first.
        {
            ASSERT(!mc_named_kms_provider_map_has(nkpm, "local:1"));
            mc_named_kms_provider_map_put(nkpm, nkp1);
            ASSERT(mc_named_kms_provider_map_has(nkpm, "local:1"));
            const mc_named_kms_provider_t *got = mc_named_kms_provider_map_get(nkpm, "local:1");
            ASSERT(got);
            ASSERT_STREQUAL(got->kms_id, "local:1");
            ASSERT(got->type == MONGOCRYPT_KMS_PROVIDER_LOCAL);
            ASSERT_CMPBUF(kek1_buf, got->value.local.key);
        }

        // Overwrite 'local:1' with a key with a different KEK.
        {
            mc_named_kms_provider_t *nkp1_with_kek2 =
                mc_named_kms_provider_new("local:1", TMP_BSON(BSON_STR({"key" : "%s"}), LOCAL_KEK2_BASE64), status);
            mc_named_kms_provider_map_put(nkpm, nkp1_with_kek2);
            ASSERT(mc_named_kms_provider_map_has(nkpm, "local:1"));
            const mc_named_kms_provider_t *got = mc_named_kms_provider_map_get(nkpm, "local:1");
            ASSERT(got);
            ASSERT_STREQUAL(got->kms_id, "local:1");
            ASSERT(got->type == MONGOCRYPT_KMS_PROVIDER_LOCAL);
            ASSERT_CMPBUF(kek2_buf, got->value.local.key);

            mc_named_kms_provider_destroy(nkp1_with_kek2);
        }
        mc_named_kms_provider_map_destroy(nkpm);
    }
    // Test getting a missing entry.
    {
        mc_named_kms_provider_map_t *nkpm = mc_named_kms_provider_map_new();
        ASSERT(!mc_named_kms_provider_map_has(nkpm, "local:2"));
        const mc_named_kms_provider_t *got = mc_named_kms_provider_map_get(nkpm, "local:2");
        ASSERT(!got);
        mc_named_kms_provider_map_destroy(nkpm);
    }

    _mongocrypt_buffer_cleanup(&kek2_buf);
    _mongocrypt_buffer_cleanup(&kek1_buf);
    mc_named_kms_provider_destroy(nkp2);
    mc_named_kms_provider_destroy(nkp1);
    mongocrypt_status_destroy(status);
}

static void test_mc_named_kms_provider_parse(_mongocrypt_tester_t *tester) {
    // Create an unused `mongocrypt_t` to initialize library with `_mongocrypt_do_init`. Otherwise, parsing base64 may
    // fail.
    {
        mongocrypt_t *unused = mongocrypt_new();
        mongocrypt_destroy(unused);
    }

    mongocrypt_status_t *status = mongocrypt_status_new();

    // Parse a valid local KMS provider.
    {
        mc_named_kms_provider_t *nkp =
            mc_named_kms_provider_new("local:name", TMP_BSON(BSON_STR({"key" : "%s"}), LOCAL_KEK1_BASE64), status);
        ASSERT_OK_STATUS(nkp != NULL, status);
        ASSERT(nkp->type == MONGOCRYPT_KMS_PROVIDER_LOCAL);
        mc_named_kms_provider_destroy(nkp);
    }

    // Parsing an unrecognized prefix is an error.
    {
        mc_named_kms_provider_t *nkp =
            mc_named_kms_provider_new("foo:name", TMP_BSON(BSON_STR({"key" : "%s"}), LOCAL_KEK1_BASE64), status);
        ASSERT_FAILS_STATUS(nkp != NULL, status, "unknown prefix");
    }

    // Parsing an empty name is an error.
    {
        mc_named_kms_provider_t *nkp =
            mc_named_kms_provider_new("local:", TMP_BSON(BSON_STR({"key" : "%s"}), LOCAL_KEK1_BASE64), status);
        ASSERT_FAILS_STATUS(nkp != NULL, status, "empty name");
    }

    // Parsing an empty prefix is an error.
    {
        mc_named_kms_provider_t *nkp =
            mc_named_kms_provider_new(":name", TMP_BSON(BSON_STR({"key" : "%s"}), LOCAL_KEK1_BASE64), status);
        ASSERT_FAILS_STATUS(nkp != NULL, status, "empty prefix");
    }

    // Parsing no prefix is an error.
    {
        mc_named_kms_provider_t *nkp =
            mc_named_kms_provider_new("local", TMP_BSON(BSON_STR({"key" : "%s"}), LOCAL_KEK1_BASE64), status);
        ASSERT_FAILS_STATUS(nkp != NULL, status, "missing colon");
    }

    // Parsing an extra colon is an error.
    {
        mc_named_kms_provider_t *nkp =
            mc_named_kms_provider_new("local:name:foo", TMP_BSON(BSON_STR({"key" : "%s"}), LOCAL_KEK1_BASE64), status);
        ASSERT_FAILS_STATUS(nkp != NULL, status, "extra colon");
    }

    mongocrypt_status_destroy(status);
}

void _mongocrypt_tester_install_named_kms_providers(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_configuring_named_kms_providers);
    INSTALL_TEST(test_mc_named_kms_provider_map);
    INSTALL_TEST(test_mc_named_kms_provider_parse);
    INSTALL_TEST(test_mongocrypt_kek_parse_with_named_kms_provider);
    INSTALL_TEST(test_create_datakey_with_named_kms_provider);
    INSTALL_TEST(test_explicit_with_named_kms_provider_for_local);
    INSTALL_TEST(test_explicit_with_named_kms_provider_for_azure);
    INSTALL_TEST(test_rewrap_with_named_kms_provider_for_local);
    INSTALL_TEST(test_mc_named_kms_provider_oauth_map);
    INSTALL_TEST(test_mc_named_kms_provider_auth_request_map);
}
