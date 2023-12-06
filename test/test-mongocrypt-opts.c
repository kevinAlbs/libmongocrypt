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
#include <test-mongocrypt.h>

#define LOCAL_KEK_BASE64                                                                                               \
    "+ol0TFyLuVvKFSqGzOFGuaOGQnnyfAqalhOv3II/VSxQTCORCGhOmw/IxhthGx0r"                                                 \
    "2R/NpMWc91qQ8Ieho4QuE9ucToTnpJ4OquFpdZv2IcO4gey3ecZGCl9jPDig8F+a"

#define BSON_STR(...) #__VA_ARGS__

static void test_mongocrypt_setopt_kms_providers(_mongocrypt_tester_t *tester) {
    // Can be called multiple times with different providers.
    {
        mongocrypt_binary_t *one = TEST_BSON(BSON_STR({"local" : {"key" : "%s"}}), LOCAL_KEK_BASE64);
        mongocrypt_binary_t *two = TEST_BSON(BSON_STR({"azure" : {"accessToken" : "bar"}}));

        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, one), crypt);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, two), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Errors if called multiple times with intersecting providers.
    {
        mongocrypt_binary_t *one = TEST_BSON(BSON_STR({"azure" : {"accessToken" : "foo"}}));
        mongocrypt_binary_t *two = TEST_BSON(BSON_STR({"azure" : {"accessToken" : "bar"}}));

        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, one), crypt);
        ASSERT_FAILS(mongocrypt_setopt_kms_providers(crypt, two), crypt, "already set");
        mongocrypt_destroy(crypt);
    }

    // Error if called multiple times with "aws".
    // Test temporarly removed due to known bug: MONGOCRYPT-TODO
    /*
    {
        mongocrypt_binary_t *bson = TEST_BSON(BSON_STR({"aws" : {"accessKeyId" : "foo", "secretAccessKey" : "bar"}}));
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "foo", -1, "bar", -1), crypt);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, bson), crypt);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, bson), crypt); // Leaks!
        // Leak is caused by overwrite to `crypt->opts->kms_providers->aws.secret_access_key`
        mongocrypt_destroy(crypt);
    }
    */
}

static void test_mongocrypt_setopt_kms_provider_local(_mongocrypt_tester_t *tester) {
    // Create an unused `mongocrypt_t` to initialize library with `_mongocrypt_do_init`. Otherwise, parsing base64 may
    // fail.
    {
        mongocrypt_t *unused = mongocrypt_new();
        mongocrypt_destroy(unused);
    }

    _mongocrypt_buffer_t local_kek_buf;
    // Create buffer for local KEK to pass data.
    {
        _mongocrypt_buffer_init(&local_kek_buf);
        _mongocrypt_buffer_resize(&local_kek_buf, MONGOCRYPT_KEY_LEN);
        int result_len = kms_message_b64_pton(LOCAL_KEK_BASE64, local_kek_buf.data, (size_t)local_kek_buf.len);
        ASSERT_CMPINT(result_len, ==, MONGOCRYPT_KEY_LEN);
    }

    // Can be called.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, _mongocrypt_buffer_as_binary(&local_kek_buf)), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Errors if called twice.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, _mongocrypt_buffer_as_binary(&local_kek_buf)), crypt);
        ASSERT_FAILS(mongocrypt_setopt_kms_provider_local(crypt, _mongocrypt_buffer_as_binary(&local_kek_buf)),
                     crypt,
                     "already set");
        mongocrypt_destroy(crypt);
    }

    // Can be followed by call to `mongocrypt_setopt_kms_providers` with different providers.
    {
        mongocrypt_binary_t *more = TEST_BSON(BSON_STR({"azure" : {"accessToken" : "foo"}}));
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, _mongocrypt_buffer_as_binary(&local_kek_buf)), crypt);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, more), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Errors if followed by call to `mongocrypt_setopt_kms_providers` configuring "local".
    // Test temporarly removed due to known bug: MONGOCRYPT-TODO
    /*
    {
        mongocrypt_binary_t *more = TEST_BSON(BSON_STR({"local" : {"key" : "%s"}}), LOCAL_KEK_BASE64);
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_local(crypt, _mongocrypt_buffer_as_binary(&local_kek_buf)), crypt);
        ASSERT_FAILS(mongocrypt_setopt_kms_providers(crypt, more), crypt, "cannot be overwritten");
        mongocrypt_destroy(crypt);
    }
    */

    _mongocrypt_buffer_cleanup(&local_kek_buf);
}

static void test_mongocrypt_setopt_kms_provider_aws(_mongocrypt_tester_t *tester) {
    // Can be called.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "foo", -1, "bar", -1), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Errors if called twice.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "foo", -1, "bar", -1), crypt);
        ASSERT_FAILS(mongocrypt_setopt_kms_provider_aws(crypt, "foo", -1, "bar", -1), crypt, "already set");
        mongocrypt_destroy(crypt);
    }

    // Can be followed by call to `mongocrypt_setopt_kms_providers` with different providers.
    {
        mongocrypt_binary_t *more = TEST_BSON(BSON_STR({"azure" : {"accessToken" : "foo"}}));
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "foo", -1, "bar", -1), crypt);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, more), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
        mongocrypt_destroy(crypt);
    }

    // Errors if followed by call to `mongocrypt_setopt_kms_providers` configuring "aws".
    // Test temporarly removed due to known bug: MONGOCRYPT-TODO
    /*
    {
        mongocrypt_binary_t *more = TEST_BSON(BSON_STR({"aws" : {"accessKeyId" : "foo", "secretAccessKey" : "bar"}}));
        mongocrypt_t *crypt = mongocrypt_new();
        ASSERT_OK(mongocrypt_setopt_kms_provider_aws(crypt, "foo", -1, "bar", -1), crypt);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, more), crypt);
        ASSERT_FAILS(mongocrypt_setopt_kms_providers(crypt, more), crypt, "cannot be overwritten");
        mongocrypt_destroy(crypt);
    }
    */
}

static void test_mongocrypt_opts_kms_providers_lookup(_mongocrypt_tester_t *tester) {
    mongocrypt_binary_t *bson = TEST_BSON(BSON_STR({"azure" : {"accessToken" : "bar"}}));

    mongocrypt_t *crypt = mongocrypt_new();
    ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, bson), crypt);
    ASSERT_OK(mongocrypt_init(crypt), crypt);

    mc_kms_creds_t got;
    ASSERT(_mongocrypt_opts_kms_providers_lookup(&crypt->opts.kms_providers, "azure", &got));
    ASSERT(got.type == MONGOCRYPT_KMS_PROVIDER_AZURE);

    ASSERT(!_mongocrypt_opts_kms_providers_lookup(&crypt->opts.kms_providers, "local", &got));
    ASSERT(got.type == MONGOCRYPT_KMS_PROVIDER_NONE);

    ASSERT(!_mongocrypt_opts_kms_providers_lookup(&crypt->opts.kms_providers, "local", &got));
    ASSERT(got.type == MONGOCRYPT_KMS_PROVIDER_NONE);

    mongocrypt_destroy(crypt);
}

void _mongocrypt_tester_install_opts(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mongocrypt_setopt_kms_providers);
    INSTALL_TEST(test_mongocrypt_setopt_kms_provider_local);
    INSTALL_TEST(test_mongocrypt_setopt_kms_provider_aws);
    INSTALL_TEST(test_mongocrypt_opts_kms_providers_lookup);
}
