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

#include "test-mongocrypt.h"

#define LOCAL_KEK_BASE64                                                                                               \
    "+ol0TFyLuVvKFSqGzOFGuaOGQnnyfAqalhOv3II/VSxQTCORCGhOmw/IxhthGx0r"                                                 \
    "2R/NpMWc91qQ8Ieho4QuE9ucToTnpJ4OquFpdZv2IcO4gey3ecZGCl9jPDig8F+a"

#define MYLOCAL_KEK_BASE64                                                                                             \
    "yPSpsO8FoVkmt+qdTDnw/pJaKriwfI6NLD1yse3BZLd3ZcXb3rAVJEA+/yu/vPzE"                                                 \
    "8ju7OYTV63AwfLor8Hg9qzo8lyYC6H3RSfdJ9g9aXdCRfGZJgpbpchJUjR06JMLR"

#define BSON_STR(...) #__VA_ARGS__

static void test_configuring_named_kms_providers(_mongocrypt_tester_t *tester) {
    // Test that a named local KMS provider can be set.
    {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_binary_t *kms_providers = TEST_BSON(BSON_STR({"local" : {"key" : "%s"}, "local:2" : {"key" : "%s"}}),
                                                       LOCAL_KEK_BASE64,
                                                       MYLOCAL_KEK_BASE64);
        bool ok = mongocrypt_setopt_kms_providers(crypt, kms_providers);
        ASSERT_OK(ok, crypt);
        mongocrypt_destroy(crypt);
    }
}

static void test_mongocrypt_named_kms_provider_parse(_mongocrypt_tester_t *tester) {
    // Create an unused `mongocrypt_t` to initialize library with `_mongocrypt_do_init`. Otherwise, parsing base64 may
    // fail.
    {
        mongocrypt_t *unused = mongocrypt_new();
        mongocrypt_destroy(unused);
    }

    mongocrypt_status_t *status = mongocrypt_status_new();

    // Parse a valid local KMS provider.
    {
        _mongocrypt_named_kms_provider_t *nkp =
            _mongocrypt_named_kms_provider_new("local:name",
                                               TMP_BSON(BSON_STR({"key" : "%s"}), MYLOCAL_KEK_BASE64),
                                               status);
        ASSERT_OK_STATUS(nkp != NULL, status);
        ASSERT(nkp->type == MONGOCRYPT_KMS_PROVIDER_LOCAL);
        _mongocrypt_named_kms_provider_destroy(nkp);
    }

    // Parsing an unrecognized prefix is an error.
    {
        _mongocrypt_named_kms_provider_t *nkp =
            _mongocrypt_named_kms_provider_new("foo:name",
                                               TMP_BSON(BSON_STR({"key" : "%s"}), MYLOCAL_KEK_BASE64),
                                               status);
        ASSERT_FAILS_STATUS(nkp != NULL, status, "unknown prefix");
    }

    // Parsing an empty name is an error.
    {
        _mongocrypt_named_kms_provider_t *nkp =
            _mongocrypt_named_kms_provider_new("local:",
                                               TMP_BSON(BSON_STR({"key" : "%s"}), MYLOCAL_KEK_BASE64),
                                               status);
        ASSERT_FAILS_STATUS(nkp != NULL, status, "empty name");
    }

    // Parsing an empty prefix is an error.
    {
        _mongocrypt_named_kms_provider_t *nkp =
            _mongocrypt_named_kms_provider_new(":name", TMP_BSON(BSON_STR({"key" : "%s"}), MYLOCAL_KEK_BASE64), status);
        ASSERT_FAILS_STATUS(nkp != NULL, status, "empty prefix");
    }

    // Parsing no prefix is an error.
    {
        _mongocrypt_named_kms_provider_t *nkp =
            _mongocrypt_named_kms_provider_new("local", TMP_BSON(BSON_STR({"key" : "%s"}), MYLOCAL_KEK_BASE64), status);
        ASSERT_FAILS_STATUS(nkp != NULL, status, "missing colon");
    }

    // Parsing an extra colon is an error.
    {
        _mongocrypt_named_kms_provider_t *nkp =
            _mongocrypt_named_kms_provider_new("local:name:foo",
                                               TMP_BSON(BSON_STR({"key" : "%s"}), MYLOCAL_KEK_BASE64),
                                               status);
        ASSERT_FAILS_STATUS(nkp != NULL, status, "extra colon");
    }

    mongocrypt_status_destroy(status);
}

void _mongocrypt_tester_install_named_kms_providers(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_configuring_named_kms_providers);
    INSTALL_TEST(test_mongocrypt_named_kms_provider_parse);
}
