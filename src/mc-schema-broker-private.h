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
#include "mongocrypt-util-private.h"
#include <bson/bson.h>

// To be moved to mc-schema-broker.c ... begin
typedef struct mc_schema_entry_t {
    char *coll;
    bool jsonSchema_has_siblings;
    bool used_local_schema;
    _mongocrypt_buffer_t jsonSchema_buf;
    mc_EncryptedFieldConfig_t encryptedFields;
    _mongocrypt_buffer_t encryptedFields_buf;
    struct mc_schema_entry_t *next;
    bool satisfied;
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
        mc_EncryptedFieldConfig_cleanup(&it->encryptedFields);
        _mongocrypt_buffer_cleanup(&it->encryptedFields_buf);
        _mongocrypt_buffer_cleanup(&it->jsonSchema_buf);
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

// mc_schema_broker_append_listCollections_filter appends a filter to a listCollections command for collections
// that still need schemas.
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

static inline bool mc_schema_entry_satisfy_from_collinfo(mc_schema_entry_t *se,
                                                         const bson_t *collinfo,
                                                         const char *coll,
                                                         const char *db,
                                                         mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(se);
    BSON_ASSERT_PARAM(collinfo);
    BSON_ASSERT_PARAM(db);
    BSON_ASSERT(!se->satisfied);

    bson_iter_t collinfo_iter;

    if (!bson_iter_init(&collinfo_iter, collinfo)) {
        CLIENT_ERR("failed to iterate collinfo for collection: %s.%s", db, coll);
        return false;
    }

    // Disallow views.
    bson_iter_t type_iter = collinfo_iter;
    if (bson_iter_find(&type_iter, "type") && BSON_ITER_HOLDS_UTF8(&type_iter) && bson_iter_utf8(&type_iter, NULL)
        && 0 == strcmp("view", bson_iter_utf8(&type_iter, NULL))) {
        CLIENT_ERR("cannot auto encrypt view: %s.%s", db, coll);
        return false;
    }

    // Check if collection is configured for QE.
    bson_iter_t encryptedFields_iter = collinfo_iter;
    if (bson_iter_find_descendant(&encryptedFields_iter, "options.encryptedFields", &encryptedFields_iter)) {
        if (!BSON_ITER_HOLDS_DOCUMENT(&encryptedFields_iter)) {
            CLIENT_ERR("expected document for `options.encryptedFields` but got %s for collection %s.%s",
                       mc_bson_type_to_string(bson_iter_type(&encryptedFields_iter)),
                       db,
                       coll);
            return false;
        }
        if (!_mongocrypt_buffer_copy_from_document_iter(&se->encryptedFields_buf, &encryptedFields_iter)) {
            CLIENT_ERR("failed to copy `options.encryptedFields` for collection: %s.%s", db, coll);
            return false;
        }
        bson_t encryptedFields_bson;
        if (!_mongocrypt_buffer_to_bson(&se->encryptedFields_buf, &encryptedFields_bson)) {
            CLIENT_ERR("unable to create BSON from `options.encryptedFields` for collection: %s.%s", db, coll);
            return false;
        }

        if (!mc_EncryptedFieldConfig_parse(&se->encryptedFields, &encryptedFields_bson, status, true /* range v2 */)) {
            return false;
        }
    }

    // Check if collection is configured for CSFLE.
    bool found_jsonSchema = false;
    bson_iter_t validator_iter = collinfo_iter;
    if (bson_iter_find_descendant(&validator_iter, "options.validator", &validator_iter)
        && BSON_ITER_HOLDS_DOCUMENT(&validator_iter)) {
        if (!bson_iter_recurse(&validator_iter, &validator_iter)) {
            CLIENT_ERR("failed to iterate `options.validator` for collection: %s.%s", db, coll);
            return false;
        }
        while (bson_iter_next(&validator_iter)) {
            const char *key = bson_iter_key(&validator_iter);
            if (0 == strcmp("$jsonSchema", key)) {
                if (found_jsonSchema) {
                    CLIENT_ERR("duplicate `$jsonSchema` fields found for collection: %s.%s", db, coll);
                    return false;
                }

                if (!_mongocrypt_buffer_copy_from_document_iter(&se->jsonSchema_buf, &validator_iter)) {
                    CLIENT_ERR("unable to copy `$jsonSchema` for collection: %s.%s", db, coll);
                    return false;
                }
                found_jsonSchema = true;
            } else {
                se->jsonSchema_has_siblings = true;
            }
        }
    }

    se->satisfied = true;
    return true;
}

static inline bool
mc_schema_broker_satisfy_from_collinfo(mc_schema_broker_t *sb, const bson_t *collinfo, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(collinfo);

    bson_iter_t collinfo_iter;

    if (!bson_iter_init(&collinfo_iter, collinfo)) {
        CLIENT_ERR("failed to iterate collinfo in database: %s", sb->db);
        return false;
    }

    // Parse the collection from the `collinfo`.
    const char *coll;
    {
        bson_iter_t name_iter = collinfo_iter;
        if (!bson_iter_find(&name_iter, "name") || !BSON_ITER_HOLDS_UTF8(&name_iter)) {
            CLIENT_ERR("failed to find 'name' in collinfo in database: %s", sb->db);
            return false;
        }
        coll = bson_iter_utf8(&name_iter, NULL);
    }

    // Find matching entry.
    mc_schema_entry_t *se = NULL;
    {
        for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
            if (0 == strcmp(it->coll, coll)) {
                se = it;
                break;
            }
        }
        if (!se) {
            CLIENT_ERR("got unexpected collinfo result for collection: %s.%s", sb->db, coll);
            return false;
        }
    }

    if (se->satisfied) {
        CLIENT_ERR("got unexpected duplicate collinfo results for collection: %s.%s", sb->db, coll);
        return false;
    }

    if (!mc_schema_entry_satisfy_from_collinfo(se, collinfo, coll, sb->db, status)) {
        return false;
    }

    return true;
}

static inline bool
mc_schema_broker_satisfy_from_schemaMap(mc_schema_broker_t *sb, const bson_t *schema_map, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(schema_map);

    for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
        if (it->satisfied) {
            continue;
        }

        bool loop_ok = false;
        char *ns = bson_strdup_printf("%s.%s", sb->db, it->coll);
        bson_iter_t iter;

        if (bson_iter_init_find(&iter, schema_map, ns)) {
            if (!_mongocrypt_buffer_copy_from_document_iter(&it->jsonSchema_buf, &iter)) {
                CLIENT_ERR("failed to read schema from schema map for collection: %s", ns);
                goto loop_fail;
            }
            it->satisfied = true;
            it->used_local_schema = true;
        }

        loop_ok = true;
    loop_fail:
        bson_free(ns);
        if (!loop_ok) {
            return false;
        }
    }
    return true;
}

static inline bool mc_schema_broker_satisfy_from_encryptedFieldsMap(mc_schema_broker_t *sb,
                                                                    const bson_t *ef_map,
                                                                    mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(ef_map);

    for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
        if (it->satisfied) {
            continue;
        }

        bool loop_ok = false;
        char *ns = bson_strdup_printf("%s.%s", sb->db, it->coll);
        bson_iter_t iter;

        if (bson_iter_init_find(&iter, ef_map, ns)) {
            if (!_mongocrypt_buffer_copy_from_document_iter(&it->encryptedFields_buf, &iter)) {
                CLIENT_ERR("failed to read encryptedFields from encryptedFields map for collection: %s", ns);
                goto loop_fail;
            }

            bson_t ef_bson;
            if (!_mongocrypt_buffer_to_bson(&it->encryptedFields_buf, &ef_bson)) {
                CLIENT_ERR("failed to create BSON from encryptedFields for collection: %s", ns);
                goto loop_fail;
            }

            if (!mc_EncryptedFieldConfig_parse(&it->encryptedFields, &ef_bson, status, true /* range v2 */)) {
                goto loop_fail;
            }

            it->satisfied = true;
            it->used_local_schema = true;
        }

        loop_ok = true;
    loop_fail:
        bson_free(ns);
        if (!loop_ok) {
            return false;
        }
    }

    return true;
}

static inline bool mc_schema_broker_satisfy_from_cache(mc_schema_broker_t *sb,
                                                       _mongocrypt_cache_t *listCollections_cache,
                                                       mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(listCollections_cache);

    for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
        if (it->satisfied) {
            continue;
        }
        char *ns = bson_strdup_printf("%s.%s", sb->db, it->coll);

        // Check if there is a listCollections result cached.
        bool loop_ok = false;
        bson_t *collinfo = NULL;
        if (!_mongocrypt_cache_get(listCollections_cache, ns, (void **)&collinfo)) {
            CLIENT_ERR("failed to retrieve from listCollections cache for entry: %s", ns);
            goto loop_fail;
        }

        if (!mc_schema_entry_satisfy_from_collinfo(it, collinfo, sb->db, it->coll, status)) {
            bson_destroy(collinfo);
            bson_free(ns);
            goto loop_fail;
        }

        loop_ok = true;
    loop_fail:
        bson_destroy(collinfo);
        bson_free(ns);
        if (!loop_ok) {
            return false;
        }
    }
    return true;
}

// mc_schema_broker_satisfy_remaining_from_empty_schemas is called when a driver signals all listCollection results
// have been fed. Assume any remaining collections have no schema.
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
    for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
        if (!it->satisfied) {
            return true;
        }
    }
    return false;
}

static inline const mc_EncryptedFieldConfig_t *mc_schema_broker_get_efc(mc_schema_broker_t *sb, size_t idx) {
    return NULL;
}

#endif // MC_SCHEMA_BROKER_PRIVATE_H
