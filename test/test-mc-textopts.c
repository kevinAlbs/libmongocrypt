/*
 * Copyright 2022-present MongoDB, Inc.
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

#include "mc-textopts-private.h"
#include "test-mongocrypt.h"

#define RAW_STRING(...) #__VA_ARGS__

static void test_mc_TextOpts_parse(_mongocrypt_tester_t *tester) {
    typedef struct {
        const char *desc;
        const char *in;
        const char *expectError;
        mc_TextOpts_t expectOpts;
    } testcase;

    testcase tests[] = {
        {.desc = "`substring` works",
         .in = RAW_STRING({"substring" : {"strMinQueryLength" : 2, "strMaxQueryLength" : 5, "strMaxLength" : 10}}),
         .expectOpts = (mc_TextOpts_t){.caseSensitive = false,
                                       .diacriticSensitive = false,
                                       .prefix = OPT_NULLOPT,
                                       .suffix = OPT_NULLOPT,
                                       .substring = {.set = true,
                                                     .strMinQueryLength = 2,
                                                     .strMaxQueryLength = 5,
                                                     .strMaxLength = OPT_I32_C(10)}}},
        {.desc = "`substring` missing `strMaxLength` fails",
         .in = RAW_STRING({"substring" : {"strMinQueryLength" : 2, "strMaxQueryLength" : 10}}),
         .expectError = "'strMaxLength' must be set for substring"},
        // TODO: add more tests.
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        testcase *test = tests + i;
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_TextOpts_t got;
        TEST_PRINTF("running test_mc_TextOpts_parse subtest: %s\n", test->desc);
        bool ret = mc_TextOpts_parse(&got, TMP_BSON_STR(test->in), status);
        if (test->expectError) {
            ASSERT_FAILS_STATUS(ret, status, test->expectError);
            continue;
        }
        ASSERT_OK_STATUS(ret, status);

        // Check expected values match:
        ASSERT_CMPINT(test->expectOpts.caseSensitive, ==, got.caseSensitive);
        ASSERT_CMPINT(test->expectOpts.diacriticSensitive, ==, got.diacriticSensitive);
        ASSERT_CMPINT(test->expectOpts.prefix.set, ==, got.prefix.set);
        if (test->expectOpts.prefix.set) {
            ASSERT_CMPINT32(test->expectOpts.prefix.strMaxQueryLength, ==, got.prefix.strMaxQueryLength);
            ASSERT_CMPINT32(test->expectOpts.prefix.strMinQueryLength, ==, got.prefix.strMinQueryLength);
        }
        ASSERT_CMPINT(test->expectOpts.prefix.set, ==, got.prefix.set);
        if (test->expectOpts.prefix.set) {
            ASSERT(!got.prefix.strMaxLength.set);
            ASSERT_CMPINT32(test->expectOpts.prefix.strMaxQueryLength, ==, got.prefix.strMaxQueryLength);
            ASSERT_CMPINT32(test->expectOpts.prefix.strMinQueryLength, ==, got.prefix.strMinQueryLength);
        }

        ASSERT_CMPINT(test->expectOpts.suffix.set, ==, got.suffix.set);
        if (test->expectOpts.suffix.set) {
            ASSERT(!got.suffix.strMaxLength.set);
            ASSERT_CMPINT32(test->expectOpts.suffix.strMaxQueryLength, ==, got.suffix.strMaxQueryLength);
            ASSERT_CMPINT32(test->expectOpts.suffix.strMinQueryLength, ==, got.suffix.strMinQueryLength);
        }

        ASSERT_CMPINT(test->expectOpts.substring.set, ==, got.substring.set);
        if (test->expectOpts.substring.set) {
            ASSERT(got.substring.strMaxLength.set);
            ASSERT_CMPINT32(test->expectOpts.substring.strMaxLength.value, ==, got.substring.strMaxLength.value);
            ASSERT_CMPINT32(test->expectOpts.substring.strMaxQueryLength, ==, got.substring.strMaxQueryLength);
            ASSERT_CMPINT32(test->expectOpts.substring.strMinQueryLength, ==, got.substring.strMinQueryLength);
        }

        mongocrypt_status_destroy(status);
    }
}

void _mongocrypt_tester_install_mc_TextOpts(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mc_TextOpts_parse);
}
