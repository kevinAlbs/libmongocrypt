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
#include "mongocrypt-key-broker-private.h"
#include "mongocrypt-private.h"
#include "mongocrypt-status-private.h"
#include "mongocrypt-util-private.h"
#include <bson/bson.h>

// To be moved to mc-schema-broker.c ... begin
typedef struct mc_schema_entry_t {
    char *coll;

    struct {
        bool set;
        bool has_siblings;
        _mongocrypt_buffer_t buf; // Owns document.
        bson_t bson;              // Non-owning view into buf.
        bool is_remote;
    } jsonSchema;

    struct {
        bool set;
        _mongocrypt_buffer_t buf; // Owns document.
        bson_t bson;              // Non-owning view into buf.
        mc_EncryptedFieldConfig_t ef;
    } encryptedFields;

    struct mc_schema_entry_t *next;
    bool satisfied; // true once a schema is applied or all sources exhausted.
} mc_schema_entry_t;

// To be moved to mc-schema-broker.c ... end

// mc_schema_broker_t stores schemas for an auto encryption operation.
typedef struct {
    char *db; // Database shared by all schemas.
    mc_schema_entry_t *ll;
    size_t ll_len;
    // TODO: add a `failed` to disallow use of the schema broker on error. Avoids needing to clean-up partially set
    // entries.
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
    if (!sb) {
        return;
    }
    mc_schema_entry_t *it = sb->ll;
    while (it != NULL) {
        bson_free(it->coll);
        // Always clean it->encryptedFields and it->jsonSchema. May be partially set.
        mc_EncryptedFieldConfig_cleanup(&it->encryptedFields.ef);
        _mongocrypt_buffer_cleanup(&it->encryptedFields.buf);
        _mongocrypt_buffer_cleanup(&it->jsonSchema.buf);
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

static inline void append_encryptedFields(const bson_t *encryptedFields, const char *coll, bson_t *out) {
    BSON_ASSERT_PARAM(encryptedFields);
    BSON_ASSERT_PARAM(out);
    BSON_ASSERT_PARAM(coll);

    bool has_escCollection = false;
    bool has_ecocCollection = false;

    bson_iter_t iter;
    BSON_ASSERT(bson_iter_init(&iter, encryptedFields));

    // Copy all values except state collections.
    while (bson_iter_next(&iter)) {
        if (strcmp(bson_iter_key(&iter), "escCollection") == 0) {
            has_escCollection = true;
        }
        if (strcmp(bson_iter_key(&iter), "ecocCollection") == 0) {
            has_ecocCollection = true;
        }
        BSON_ASSERT(BSON_APPEND_VALUE(out, bson_iter_key(&iter), bson_iter_value(&iter)));
    }

    if (!has_escCollection) {
        char *default_escCollection = bson_strdup_printf("enxcol_.%s.esc", coll);
        BSON_ASSERT(BSON_APPEND_UTF8(out, "escCollection", default_escCollection));
        bson_free(default_escCollection);
    }

    if (!has_ecocCollection) {
        char *default_ecocCollection = bson_strdup_printf("enxcol_.%s.ecoc", coll);
        BSON_ASSERT(BSON_APPEND_UTF8(out, "ecocCollection", default_ecocCollection));
        bson_free(default_ecocCollection);
    }
}

static inline bool
mc_schema_broker_append_encryptionInformation(const mc_schema_broker_t *sb, bson_t *out, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(out);

    // Check if any collection has encryptedFields.
    bool has_encryptedFields = false;
    const char *coll_with_encryptedFields = NULL;
    for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
        BSON_ASSERT(it->satisfied);
        if (it->encryptedFields.set) {
            has_encryptedFields = true;
            coll_with_encryptedFields = it->coll;
            break;
        }
    }

    if (has_encryptedFields) {
        // If any collection has encryptedFields, error if any collection only has a JSON Schema.
        for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
            BSON_ASSERT(it->satisfied);
            if (!it->encryptedFields.set && it->jsonSchema.set) {
                const char *coll_with_jsonSchema = it->coll;
                CLIENT_ERR("Collection '%s' has encryptedFields but collection '%s' has a JSON schema configured. To "
                           "ignore the JSON schema, add '%s' to encryptedFieldsMap.",
                           coll_with_encryptedFields,
                           coll_with_jsonSchema,
                           coll_with_jsonSchema);
                return false;
            }
        }
    } else {
        // Not needed.
        return true;
    }

    bson_t encryption_information_bson;
    BSON_ASSERT(BSON_APPEND_DOCUMENT_BEGIN(out, "encryptionInformation", &encryption_information_bson));
    BSON_ASSERT(BSON_APPEND_INT32(&encryption_information_bson, "type", 1));

    bson_t schema_bson;
    BSON_ASSERT(BSON_APPEND_DOCUMENT_BEGIN(&encryption_information_bson, "schema", &schema_bson));

    for (mc_schema_entry_t *se = sb->ll; se != NULL; se = se->next) {
        BSON_ASSERT(se->satisfied);
        char *ns = bson_strdup_printf("%s.%s", sb->db, se->coll);
        if (!se->encryptedFields.set) {
            bson_t empty = BSON_INITIALIZER;
            BSON_ASSERT(BSON_APPEND_DOCUMENT(&schema_bson, ns, &empty));
        } else {
            bson_t ns_to_schema_bson;
            BSON_ASSERT(BSON_APPEND_DOCUMENT_BEGIN(&schema_bson, ns, &ns_to_schema_bson));
            append_encryptedFields(&se->encryptedFields.bson, se->coll, &ns_to_schema_bson);
            BSON_ASSERT(bson_append_document_end(&schema_bson, &ns_to_schema_bson));
        }
        bson_free(ns);
    }
    BSON_ASSERT(bson_append_document_end(&encryption_information_bson, &schema_bson));
    BSON_ASSERT(bson_append_document_end(out, &encryption_information_bson));
    return true;
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
        if (!_mongocrypt_buffer_copy_from_document_iter(&se->encryptedFields.buf, &encryptedFields_iter)) {
            CLIENT_ERR("failed to copy `options.encryptedFields` for collection: %s.%s", db, coll);
            return false;
        }

        if (!_mongocrypt_buffer_to_bson(&se->encryptedFields.buf, &se->encryptedFields.bson)) {
            CLIENT_ERR("unable to create BSON from `options.encryptedFields` for collection: %s.%s", db, coll);
            return false;
        }

        if (!mc_EncryptedFieldConfig_parse(&se->encryptedFields.ef,
                                           &se->encryptedFields.bson,
                                           status,
                                           true /* range v2 */)) {
            return false;
        }
        se->encryptedFields.set = true;
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

                if (!_mongocrypt_buffer_copy_from_document_iter(&se->jsonSchema.buf, &validator_iter)) {
                    CLIENT_ERR("unable to copy `$jsonSchema` for collection: %s.%s", db, coll);
                    return false;
                }

                if (!_mongocrypt_buffer_to_bson(&se->jsonSchema.buf, &se->jsonSchema.bson)) {
                    CLIENT_ERR("unable to create BSON from `$jsonSchema` for collection: %s.%s", db, coll);
                    return false;
                }

                found_jsonSchema = true;
            } else {
                se->jsonSchema.has_siblings = true;
                break;
            }
            BSON_ASSERT(!se->jsonSchema.set);
            se->jsonSchema.set = true;
            se->jsonSchema.is_remote = true;
        }
    }

    se->satisfied = true;
    return true;
}

static inline bool mc_schema_broker_satisfy_from_collinfo(mc_schema_broker_t *sb,
                                                          const bson_t *collinfo,
                                                          _mongocrypt_cache_t *collinfo_cache,
                                                          mongocrypt_status_t *status) {
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

    bson_iter_t type_iter = collinfo_iter;
    if (bson_iter_find(&type_iter, "type") && BSON_ITER_HOLDS_UTF8(&type_iter)
        && 0 == strcmp("view", bson_iter_utf8(&type_iter, NULL))) {
        CLIENT_ERR("cannot auto encrypt a view: %s.%s", sb->db, coll);
        return false;
    }

    // Cache the received collinfo.
    {
        char *ns = bson_strdup_printf("%s.%s", sb->db, coll);
        if (!_mongocrypt_cache_add_copy(collinfo_cache, ns, (void *)collinfo, status)) {
            bson_free(ns);
            return false;
        }
        bson_free(ns);
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
            if (!_mongocrypt_buffer_copy_from_document_iter(&it->jsonSchema.buf, &iter)) {
                CLIENT_ERR("failed to read schema from schema map for collection: %s", ns);
                goto loop_fail;
            }

            if (!_mongocrypt_buffer_to_bson(&it->jsonSchema.buf, &it->jsonSchema.bson)) {
                CLIENT_ERR("unable to create BSON from schema map for collection: %s", ns);
                goto loop_fail;
            }

            BSON_ASSERT(!it->jsonSchema.set);
            it->jsonSchema.set = true;
            it->jsonSchema.is_remote = false;
            it->satisfied = true;
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
            if (!_mongocrypt_buffer_copy_from_document_iter(&it->encryptedFields.buf, &iter)) {
                CLIENT_ERR("failed to read encryptedFields from encryptedFields map for collection: %s", ns);
                goto loop_fail;
            }

            if (!_mongocrypt_buffer_to_bson(&it->encryptedFields.buf, &it->encryptedFields.bson)) {
                CLIENT_ERR("failed to create BSON from encryptedFields map for collection: %s", ns);
                goto loop_fail;
            }

            if (!mc_EncryptedFieldConfig_parse(&it->encryptedFields.ef,
                                               &it->encryptedFields.bson,
                                               status,
                                               true /* range v2 */)) {
                goto loop_fail;
            }

            BSON_ASSERT(!it->encryptedFields.set);
            it->encryptedFields.set = true;
            it->satisfied = true;
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

        if (!collinfo) {
            goto loop_skip;
        }

        if (!mc_schema_entry_satisfy_from_collinfo(it, collinfo, sb->db, it->coll, status)) {
            bson_destroy(collinfo);
            bson_free(ns);
            goto loop_fail;
        }

    loop_skip:
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
                                                                         _mongocrypt_cache_t *collinfo_cache,
                                                                         mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);

    for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
        if (it->satisfied) {
            continue;
        }

        // Cache the received collinfo.
        {
            char *ns = bson_strdup_printf("%s.%s", sb->db, it->coll);
            bson_t empty = BSON_INITIALIZER;
            if (!_mongocrypt_cache_add_copy(collinfo_cache, ns, &empty, status)) {
                bson_destroy(&empty);
                bson_free(ns);
                return false;
            }
            bson_destroy(&empty);
            bson_free(ns);
        }

        it->satisfied = true;
    }

    return true;
}

// mc_schema_broker_append_csfleEncryptionSchemas appends schema information to send to QA.
// For only one JSON schema, use `jsonSchema` for backwards compatibility.
// For multiple JSON schemas, use `csfleEncryptionSchemas` (added in server 8.2).
static inline bool
mc_schema_broker_append_csfleEncryptionSchemas(mc_schema_broker_t *sb, bson_t *out, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(out);

    // Check if any collection has encryptedFields.
    bool has_encryptedFields = false;
    const char *coll_with_encryptedFields = NULL;
    for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
        BSON_ASSERT(it->satisfied);
        if (it->encryptedFields.set) {
            has_encryptedFields = true;
            coll_with_encryptedFields = it->coll;
            break;
        }
    }

    if (has_encryptedFields) {
        // If any collection has encryptedFields, error if any collection only has a JSON Schema.
        for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
            BSON_ASSERT(it->satisfied);
            if (!it->encryptedFields.set && it->jsonSchema.set) {
                const char *coll_with_jsonSchema = it->coll;
                CLIENT_ERR("Collection '%s' has encryptedFields but collection '%s' has a JSON schema configured. To "
                           "ignore the JSON schema, add '%s' to encryptedFieldsMap.",
                           coll_with_encryptedFields,
                           coll_with_jsonSchema,
                           coll_with_jsonSchema);
                return false;
            }
        }
        // Handle encryptedFields in mc_schema_broker_append_encryptionInformation
        return true;
    }

    if (sb->ll_len == 1) {
        // Append the only jsonSchema with the "jsonSchema" field.
        mc_schema_entry_t *se = sb->ll;
        BSON_ASSERT(se);
        BSON_ASSERT(!se->next);
        BSON_ASSERT(se->satisfied);
        if (se->jsonSchema.set) {
            BSON_ASSERT(BSON_APPEND_DOCUMENT(out, "jsonSchema", &se->jsonSchema.bson));
            BSON_ASSERT(BSON_APPEND_BOOL(out, "isRemoteSchema", se->jsonSchema.is_remote));
        } else {
            bson_t empty = BSON_INITIALIZER;
            BSON_ASSERT(BSON_APPEND_DOCUMENT(out, "jsonSchema", &empty));
            BSON_ASSERT(BSON_APPEND_BOOL(out, "isRemoteSchema", false));
        }
        return true;
    }

    // Append multiple schemas as "csfleEncryptionSchemas"
    bson_t csfleEncryptionSchemas;
    BSON_ASSERT(BSON_APPEND_DOCUMENT_BEGIN(out, "csfleEncryptionSchemas", &csfleEncryptionSchemas));

    for (mc_schema_entry_t *se = sb->ll; se != NULL; se = se->next) {
        BSON_ASSERT(se->satisfied);

        char *ns = bson_strdup_printf("%s.%s", sb->db, se->coll);
        bson_t ns_to_doc;
        BSON_ASSERT(BSON_APPEND_DOCUMENT_BEGIN(&csfleEncryptionSchemas, ns, &ns_to_doc));
        bson_free(ns);

        if (!se->jsonSchema.set) {
            // Append as an empty document.
            bson_t empty = BSON_INITIALIZER;
            BSON_ASSERT(BSON_APPEND_DOCUMENT(&ns_to_doc, "schema", &empty));
            BSON_ASSERT(BSON_APPEND_BOOL(&ns_to_doc, "isRemoteSchema", false));
        } else {
            BSON_ASSERT(BSON_APPEND_DOCUMENT(&ns_to_doc, "schema", &se->jsonSchema.bson));
            BSON_ASSERT(BSON_APPEND_BOOL(&ns_to_doc, "isRemoteSchema", se->jsonSchema.is_remote));
        }
        BSON_ASSERT(bson_append_document_end(&csfleEncryptionSchemas, &ns_to_doc));
    }

    BSON_ASSERT(bson_append_document_end(out, &csfleEncryptionSchemas));

    return true;
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

static inline const mc_EncryptedFieldConfig_t *
mc_schema_broker_get_encryptedFields(mc_schema_broker_t *sb, const char *coll, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(sb);
    BSON_ASSERT_PARAM(coll);
    for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
        if (0 != strcmp(it->coll, coll)) {
            continue;
        }
        if (!it->satisfied) {
            CLIENT_ERR("Expected encryptedFields for '%s', but schema request not satisfied", coll);
            return NULL;
        }
        if (!it->encryptedFields.set) {
            CLIENT_ERR("Expected encryptedFields for '%s', but none set", coll);
            return NULL;
        }
        return &it->encryptedFields.ef;
    }
    CLIENT_ERR("Expected encryptedFields for '%s', but did not find entry", coll);
    return NULL;
}

static inline bool mc_schema_broker_satisfy_from_create_or_collMod(mc_schema_broker_t *sb,
                                                                   const bson_t *cmd,
                                                                   mongocrypt_status_t *status) {
    bson_iter_t iter;
    if (!bson_iter_init(&iter, cmd) || !bson_iter_next(&iter)) {
        CLIENT_ERR("Failed to get command name");
        return false;
    }

    const char *cmd_name = bson_iter_key(&iter);
    if (0 != strcmp(cmd_name, "create") && 0 != strcmp(cmd_name, "collMod")) {
        // Ignore other commands.
        return true;
    }

    if (!BSON_ITER_HOLDS_UTF8(&iter)) {
        CLIENT_ERR("Failed to get collection name from command");
        return false;
    }
    const char *coll = bson_iter_utf8(&iter, NULL);

    // Check if schema was requested.
    mc_schema_entry_t *found = NULL;
    for (mc_schema_entry_t *it = sb->ll; it != NULL; it = it->next) {
        if (0 == strcmp(it->coll, coll)) {
            found = it;
            break;
        }
    }

    if (!found) {
        // Command is for a collection that is not needed.
        return true;
    }

    if (found->satisfied) {
        return true;
    }

    if (bson_iter_find_descendant(&iter, "validator.$jsonSchema", &iter)) {
        if (!_mongocrypt_buffer_copy_from_document_iter(&found->jsonSchema.buf, &iter)) {
            CLIENT_ERR("failed to read schema from schema map for collection: %s", coll);
            return false;
        }

        if (!_mongocrypt_buffer_to_bson(&found->jsonSchema.buf, &found->jsonSchema.bson)) {
            CLIENT_ERR("unable to create BSON from schema map for collection: %s", coll);
            return false;
        }

        found->jsonSchema.set = true;
        found->satisfied = true;
        return true;
    }

    // Command does not have a schema. Not an error.
    return true;
}

#endif // MC_SCHEMA_BROKER_PRIVATE_H
