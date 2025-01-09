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

// To be moved to mc-schema-broker.c ... begin
typedef struct mc_schema_entry_t {
    char *coll;
    struct mc_schema_entry_t *next;
} mc_schema_entry_t;

// To be moved to mc-schema-broker.c ... end

// mc_schema_broker_t stores schemas for an auto encryption operation.
typedef struct {
    char *db; // Database shared by all schemas.
    mc_schema_entry_t *ll;
    size_t ll_len;
} mc_schema_broker_t;

static inline mc_schema_broker_t *mc_schema_broker_new(void) {
    return bson_malloc0(sizeof(mc_schema_broker_t));
}

// mc_schema_broker_request adds a namespace to request a schema. Ignores duplicates.
// Returns error if two requests have different databases.
static inline bool
mc_schema_broker_request(mc_schema_broker_t *sb, const char *db, const char *coll, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(db);
    BSON_ASSERT_PARAM(coll);

    if (sb->db && 0 != strcmp(sb->db, db)) {
        CLIENT_ERR("Cannot request schemas for different databases. Requested schemas for '%s' and '%s'.", sb->db, db);
        return false;
    }

    // Check for duplicates. Keep pointer to last node.
    mc_schema_entry_t *last = NULL;
    for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
        if (0 == strcmp(it->coll, coll)) {
            return true;
        }
        last = it;
    }

    mc_schema_entry_t *se = bson_malloc0(sizeof *se);
    se->coll = bson_strdup(coll);
    if (NULL == last) {
        sb->ll = se;
        sb->db = bson_strdup(db);
    } else {
        last->next = se;
    }
    sb->ll_len++;
    return true;
}

static inline void mc_schema_broker_destroy(mc_schema_broker_t *sb) {
    mc_schema_entry_t *it = sb->ll;
    while (it != NULL) {
        bson_free(it->coll);
        mc_schema_entry_t *tmp = it->next;
        bson_free(it);
        it = tmp;
    }
    bson_free(sb->db);
    bson_free(sb);
    return;
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

    if (sb->ll_len == 0) {
        CLIENT_ERR("Unexpected: attempting to create listCollections filter but no schemas requested");
        return false;
    } else if (sb->ll_len == 1) {
        // One request. Append as: { "name": <name> }
        BCON_APPEND(out, "name", BCON_UTF8(sb->ll->coll));
        return true;
    } else {
        // Multiple requests. Append as: { "name": { "$in": [ <name1>, <name2>, ... ] } }
        bson_t in;
        BSON_ASSERT(BSON_APPEND_DOCUMENT_BEGIN(out, "name", &in));
        bson_array_builder_t *bab;
        BSON_ASSERT(BSON_APPEND_ARRAY_BUILDER_BEGIN(&in, "$in", &bab));
        for (mc_schema_entry_t *se = sb->ll; se != NULL; se = se->next) {
            BSON_ASSERT(bson_array_builder_append_utf8(bab, se->coll, -1));
            // TODO: do not request schemas that are already satisfied.
        }
        BSON_ASSERT(bson_append_array_builder_end(&in, bab));
        BSON_ASSERT(bson_append_document_end(out, &in));
    }
    return true;
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

static inline const mc_EncryptedFieldConfig_t *mc_schema_broker_get_efc(mc_schema_broker_t *sb, size_t idx) {
    return NULL;
}

#endif // MC_SCHEMA_BROKER_PRIVATE_H
