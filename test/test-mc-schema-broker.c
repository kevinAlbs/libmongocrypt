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
        bson_t filter = BSON_INITIALIZER;
        ASSERT_OK_STATUS(mc_schema_broker_append_listCollections_filter(sb, &filter, status), status);
        ASSERT_EQUAL_BSON(TMP_BSON(BSON_STR({"name" : "coll"})), &filter);
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
        bson_t filter = BSON_INITIALIZER;
        ASSERT_OK_STATUS(mc_schema_broker_append_listCollections_filter(sb, &filter, status), status);
        ASSERT_EQUAL_BSON(TMP_BSON(BSON_STR({"name" : {"$in" : [ "coll1", "coll2" ]}})), &filter);
        bson_destroy(&filter);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Duplicates are ignored.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll1", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll1", status), status);

        // Check listCollections filter:
        bson_t filter = BSON_INITIALIZER;
        ASSERT_OK_STATUS(mc_schema_broker_append_listCollections_filter(sb, &filter, status), status);
        ASSERT_EQUAL_BSON(TMP_BSON(BSON_STR({"name" : "coll1"})), &filter);
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

static void test_mc_schema_broker_satisfy_from_collInfo(_mongocrypt_tester_t *tester) {
    bson_t *collinfo_jsonSchema = TEST_FILE_AS_BSON("./test/data/schema-broker/collinfo-jsonSchema.json");

    // Can satisfy with collinfo containing $jsonSchema.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_jsonSchema, status), status);
        ASSERT(!mc_scheme_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Can satisfy with collinfo containing encryptedFields.
    {
        bson_t *collinfo_encryptedFields = TEST_FILE_AS_BSON("./test/data/schema-broker/collinfo-encryptedFields.json");
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_encryptedFields, status), status);
        ASSERT(!mc_scheme_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Can satisfy with collinfo containing no schema.
    {
        bson_t *collinfo_noSchema = TEST_FILE_AS_BSON("./test/data/schema-broker/collinfo-noSchema.json");
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_noSchema, status), status);
        ASSERT(!mc_scheme_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Errors if attempting to satisfy a non-requested collection.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "different", status), status);
        ASSERT_FAILS_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_jsonSchema, status),
                            status,
                            "got unexpected collinfo result");

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Errors if attempting to satisfy an already satisfied collection.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_jsonSchema, status), status);
        ASSERT_FAILS_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_jsonSchema, status),
                            status,
                            "got unexpected duplicate");

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Errors if attempting to satisfy with an empty document.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_FAILS_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, TMP_BSON("{}"), status),
                            status,
                            "failed to find 'name'");

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_schema_broker_satisfy_from_cache(_mongocrypt_tester_t *tester) {
    bson_t *collinfo = TEST_FILE_AS_BSON("./test/data/schema-broker/collinfo-jsonSchema.json");

    // Can satisfy.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();

        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);
        ASSERT_OR_PRINT(_mongocrypt_cache_add_copy(&cache, "db.coll", collinfo, status), status);

        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_cache(sb, &cache, status), status);
        ASSERT(!mc_scheme_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
        _mongocrypt_cache_cleanup(&cache);
    }

    // Can satisfy with empty entry.
    {
        // An empty entry is cached when there is none on the server (e.g. the collection was not created on the server)
        mongocrypt_status_t *status = mongocrypt_status_new();

        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);
        ASSERT_OR_PRINT(_mongocrypt_cache_add_copy(&cache, "db.coll", TMP_BSON("{}"), status), status);

        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_cache(sb, &cache, status), status);
        ASSERT(!mc_scheme_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
        _mongocrypt_cache_cleanup(&cache);
    }
}

static void test_mc_schema_broker_satisfy_from_schemaMap(_mongocrypt_tester_t *tester) {
    bson_t *schemaMap = TEST_FILE_AS_BSON("./test/data/schema-broker/schemaMap.json");

    // Can satisfy.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, schemaMap, status), status);
        ASSERT(!mc_scheme_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Does not satisfy with non-matching entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, TMP_BSON("{'db.foo': {}}"), status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb)); // Still not satisfied.

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Can satisfy with empty entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, TMP_BSON("{'db.coll': {}}"), status), status);
        ASSERT(!mc_scheme_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_schema_broker_satisfy_from_encryptedFieldsMap(_mongocrypt_tester_t *tester) {
    bson_t *encryptedFieldsMap = TEST_FILE_AS_BSON("./test/data/schema-broker/encryptedFieldsMap.json");

    // Can satisfy.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_scheme_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Does not satisfy with non-matching entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, TMP_BSON("{'db.foo': {}}"), status),
                         status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb)); // Still not satisfied.

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Fails to satisfy with empty entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_scheme_broker_need_more_schemas(sb));
        ASSERT_FAILS_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, TMP_BSON("{'db.coll': {}}"), status),
                            status,
                            "unable to find 'fields'");

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

void _mongocrypt_tester_install_mc_schema_broker(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mc_schema_broker_request);
    INSTALL_TEST(test_mc_schema_broker_satisfy_from_collInfo);
    INSTALL_TEST(test_mc_schema_broker_satisfy_from_cache);
    INSTALL_TEST(test_mc_schema_broker_satisfy_from_schemaMap);
    INSTALL_TEST(test_mc_schema_broker_satisfy_from_encryptedFieldsMap);
}
