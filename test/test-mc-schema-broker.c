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

#include "mc-schema-broker-private.h"

#include "test-mongocrypt.h"

static void test_mc_schema_broker_request(_mongocrypt_tester_t *tester) {
    // Can request.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);

        // Check listCollections filter:
        bson_t filter;
        ASSERT_OK_STATUS(mc_schema_broker_append_listCollections_filter(sb, &filter, status), status);
        ASSERT_EQUAL_BSON(TMP_BSON(BSON_STR({"foo" : "bar"})), &filter);
        bson_destroy(&filter);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Can request two collections.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll1", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);

        // Check listCollections filter:
        bson_t filter;
        ASSERT_OK_STATUS(mc_schema_broker_append_listCollections_filter(sb, &filter, status), status);
        ASSERT_EQUAL_BSON(TMP_BSON(BSON_STR({"foo" : "bar"})), &filter);
        bson_destroy(&filter);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Duplicates are ignored.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll1", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);

        // Check listCollections filter:
        bson_t filter;
        ASSERT_OK_STATUS(mc_schema_broker_append_listCollections_filter(sb, &filter, status), status);
        ASSERT_EQUAL_BSON(TMP_BSON(BSON_STR({"foo" : "bar"})), &filter);
        bson_destroy(&filter);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Errors if requesting two collections on different databases.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db1", "coll1", status), status);
        ASSERT_FAILS_STATUS(mc_schema_broker_request(sb, "db2", "coll2", status),
                            status,
                            "Cannot request schemas for different databases");

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

void _mongocrypt_tester_install_mc_schema_broker(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mc_schema_broker_request);
}
