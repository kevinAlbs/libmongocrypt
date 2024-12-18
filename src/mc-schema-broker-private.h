/*
 * Copyright 2024-present MongoDB, Inc.
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

#ifndef MC_SCHEMA_BROKER_PRIVATE_H
#define MC_SCHEMA_BROKER_PRIVATE_H

#include "mc-efc-private.h" // mc_EncryptedFieldConfig_t
#include "mongocrypt-cache-collinfo-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-status-private.h"
#include <bson/bson.h>

// mc_schema_broker_t stores schemas for an auto encryption operation.
typedef struct {
    int placeholder;
} mc_schema_broker_t;

static inline mc_schema_broker_t *mc_schema_broker_new(void) {
    return bson_malloc0(sizeof(mc_schema_broker_t));
}

// mc_schema_broker_request adds a namespace to request a schema. Ignores duplicates.
static inline void mc_schema_broker_request(mc_schema_broker_t *sb, const char *db, const char *coll) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(db);
    BSON_ASSERT_PARAM(coll);
}

static inline bool mc_schema_broker_has_any_csfle_schemas(const mc_schema_broker_t *sb) {
    BSON_ASSERT_PARAM(sb);
    return false;
}

static inline bool mc_schema_broker_has_any_qe_schemas(const mc_schema_broker_t *sb) {
    BSON_ASSERT_PARAM(sb);
    return false;
}

static inline bool mc_schema_broker_has_multiple_ns(const mc_schema_broker_t *sb) {
    BSON_ASSERT_PARAM(sb);
    return false;
}

static inline bool
mc_schema_broker_append_listCollections_filter(const mc_schema_broker_t *sb, bson_t *out, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(out);
    CLIENT_ERR("mc_schema_broker_append_listCollections_filter is not yet implemented");
    return false;
}

static inline bool
mc_schema_broker_append_encryptionInformation(const mc_schema_broker_t *sb, bson_t *out, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(out);
    CLIENT_ERR("mc_schema_broker_append_encryptionInformation is not yet implemented");
    return false;
}

static inline bool mc_schema_broker_satisfy_from_collinfo(mc_schema_broker_t *sb,
                                                          const char *ns,
                                                          const bson_t *collinfo,
                                                          mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(ns);
    BSON_ASSERT_PARAM(collinfo);
    CLIENT_ERR("mc_schema_broker_satisfy_from_collinfo is not yet implemented");
    return false;
}

static inline bool
mc_schema_broker_satisfy_from_schemaMap(mc_schema_broker_t *sb, const bson_t *schema_map, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(schema_map);
    CLIENT_ERR("mc_schema_broker_satisfy_from_schemaMap is not yet implemented");
    return false;
}

static inline bool mc_schema_broker_satisfy_from_encryptedFieldsMap(mc_schema_broker_t *sb,
                                                                    const bson_t *ef_map,
                                                                    mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(ef_map);
    CLIENT_ERR("mc_schema_broker_satisfy_from_encryptedFieldsMap is not yet implemented");
    return false;
}

static inline bool mc_schema_broker_satisfy_from_cache(mc_schema_broker_t *sb,
                                                       const _mongocrypt_cache_t *listCollections_cache,
                                                       mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(listCollections_cache);
    CLIENT_ERR("mc_schema_broker_satisfy_from_cache is not yet implemented");
    return false;
}

// mc_schema_broker_satisfy_remaining_from_empty_schemas is called when a driver signals all listCollection results have
// been fed. Assume any remaining collections have no schema.
static inline bool mc_schema_broker_satisfy_remaining_with_empty_schemas(mc_schema_broker_t *sb,
                                                                         mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    CLIENT_ERR("mc_schema_broker_satisfy_remaining_with_empty_schemas is not yet implemented");
    return false;
}

static inline bool mc_schema_broker_apply_to_cache(mc_schema_broker_t *sb,
                                                   _mongocrypt_cache_t *listCollections_cache,
                                                   mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(listCollections_cache);
    CLIENT_ERR("mc_schema_broker_apply_to_cache is not yet implemented");
    return false;
}

// mc_schema_broker_append_csfleEncryptionSchemas appends JSON schemas for CSFLE to send to QA.
// For only one schema, use `jsonSchema` for backwards compatibility.
// For multiple schemas, use `csfleEncryptionSchemas` (added in server 8.2).
static inline bool
mc_schema_broker_append_csfleEncryptionSchemas(mc_schema_broker_t *sb, bson_t *out, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(out);
    CLIENT_ERR("mc_schema_broker_append_csfleEncryptionSchemas is not yet implemented");
    return false;
}

static inline bool mc_scheme_broker_need_more_schemas(mc_schema_broker_t *sb) {
    BSON_ASSERT_PARAM(sb);
    return false;
}

static inline void mc_schema_broker_destroy(mc_schema_broker_t *sb) {
    return;
}

#endif // MC_SCHEMA_BROKER_PRIVATE_H
