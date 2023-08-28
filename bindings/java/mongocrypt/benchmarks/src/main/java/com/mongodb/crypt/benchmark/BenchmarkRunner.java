package com.mongodb.crypt.benchmark;
import com.mongodb.crypt.capi.*;
import org.bson.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;

public class BenchmarkRunner {
    static final int NUM_FIELDS = 1500;
    static final int RUNS = 128;
    static int NUM_SECS = 10;
    static final byte[] LOCAL_MASTER_KEY = new byte[]{
            -99, -108, 75, 13, -109, -48, -59, 68, -91, 114, -3, 50, 27, -108, 48, -112, 35, 53,
            115, 124, -16, -10, -62, -12, -38, 35, 86, -25, -113, 4, -52, -6, -34, 117, -76, 81,
            -121, -13, -117, -105, -41, 75, 68, 59, -84, 57, -94, -58, 77, -111, 0, 62, -47, -6, 74,
            48, -63, -46, -58, 94, -5, -84, 65, -14, 72, 19, 60, -101, 80, -4, -89, 36, 122, 46, 2,
            99, -93, -58, 22, 37, 81, 80, 120, 62, 15, -40, 110, -124, -90, -20, -115, 45, 36, 71,
            -27, -81
    };

    // `keyDocumentString` represents a Data Encryption Key (DEK) encrypted with the Key Encryption Key (KEK) `LOCAL_MASTER_KEY`.
    static final String keyDocumentString = """
            {
              "_id": {
                "$binary": {
                  "base64": "YWFhYWFhYWFhYWFhYWFhYQ==",
                  "subType": "04"
                }
              },
              "keyMaterial": {
                "$binary": {
                  "base64": "ACR7Hm33dDOAAD7l2ubZhSpSUWK8BkALUY+qW3UgBAEcTV8sBwZnaAWnzDsmrX55dgmYHWfynDlJogC/e33u6pbhyXvFTs5ow9OLCuCWBJ39T/Ivm3kMaZJybkejY0V+uc4UEdHvVVz/SbitVnzs2WXdMGmo1/HmDRrxGYZjewFslquv8wtUHF5pyB+QDlQBd/al9M444/8bJZFbMSmtIg==",
                  "subType": "00"
                }
              },
              "creationDate": {
                "$date": "2023-08-21T14:28:20.875Z"
              },
              "updateDate": {
                "$date": "2023-08-21T14:28:20.875Z"
              },
              "status": 0,
              "masterKey": {
                "provider": "local"
              }
            }
     """;

    private static MongoCrypt createMongoCrypt() {
        return MongoCrypts.create(MongoCryptOptions
                .builder()
                .awsKmsProviderOptions(MongoAwsKmsProviderOptions.builder()
                        .accessKeyId("example")
                        .secretAccessKey("example")
                        .build())
                .localKmsProviderOptions(MongoLocalKmsProviderOptions.builder()
                        .localMasterKey(ByteBuffer.wrap(LOCAL_MASTER_KEY))
                        .build())
                .build());
    }

    private static double measureMedianDurationOfDecrypt (MongoCrypt mongoCrypt, BsonDocument toDecrypt) {
        ArrayList<Long> durations = new ArrayList<Long>(RUNS);
        // Attempt to measure median operation time.
        for (int i = 0; i < RUNS; i++) {
            long start = System.nanoTime();
            try (MongoCryptContext ctx = mongoCrypt.createDecryptionContext(toDecrypt)) {
                assert ctx.getState() == MongoCryptContext.State.READY;
                RawBsonDocument result = ctx.finish();
                int gotSize = result.size();
                if (gotSize != NUM_FIELDS) {
                    throw new RuntimeException("Expected size: " + NUM_FIELDS + ", got " + gotSize);
                }
            }
            durations.add(System.nanoTime() - start);
        }

        Collections.sort(durations);
        long medianDuration = durations.get(RUNS / 2);
        return medianDuration / 1_000.0;
    }

    private static long measureMedianOpsPerSecOfDecrypt (MongoCrypt mongoCrypt, BsonDocument toDecrypt) {
        ArrayList<Long> opsPerSecs = new ArrayList<Long>(NUM_SECS);
        for (int i = 0; i < NUM_SECS; i++) {
            long opsPerSec = 0;
            long start = System.nanoTime();
            // Run for one second.
            while (System.nanoTime() - start < 1_000_000_000) {
                try (MongoCryptContext ctx = mongoCrypt.createDecryptionContext(toDecrypt)) {
                    assert ctx.getState() == MongoCryptContext.State.READY;
                    RawBsonDocument result = ctx.finish();
                    int gotSize = result.size();
                    if (gotSize != NUM_FIELDS) {
                        throw new RuntimeException("Expected size: " + NUM_FIELDS + ", got " + gotSize);
                    }
                    opsPerSec++;
                }
            }
            opsPerSecs.add(opsPerSec);
        }
        Collections.sort(opsPerSecs);
        return opsPerSecs.get(NUM_SECS / 2);
    }

    public static void main(String[] args) {
        if (System.getenv("QUICK") != null && System.getenv("QUICK").equals("ON")) {
            System.out.printf("QUICK=ON is set. Using NUM_SECS=3%n");
            NUM_SECS=3;
        }
        System.out.printf ("BenchmarkRunner is using libmongocrypt version=%s, RUNS=%d, NUM_SECS=%d%n", CAPI.mongocrypt_version(null).toString(), RUNS, NUM_SECS);
        BsonDocument keyDocument = BsonDocument.parse (keyDocumentString);
        try (MongoCrypt mongoCrypt = createMongoCrypt()) {
            // `encrypted` will contain encrypted fields.
            BsonDocument encrypted = new BsonDocument();
            // `notEncrypted` is a copy of `encrypted` with the binary subtypes changed to prevent decryption. It is used as a baseline.
            BsonDocument notEncrypted = new BsonDocument();
            {
                for (int i = 0; i < NUM_FIELDS; i++) {
                    MongoExplicitEncryptOptions options = MongoExplicitEncryptOptions.builder()
                            .keyId(new BsonBinary(BsonBinarySubType.UUID_STANDARD, Base64.getDecoder().decode("YWFhYWFhYWFhYWFhYWFhYQ==")))
                            .algorithm("AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic")
                            .build();
                    BsonDocument toEncrypt = new BsonDocument("v", new BsonString(String.format("value %04d", i)));
                    try (MongoCryptContext ctx = mongoCrypt.createExplicitEncryptionContext(toEncrypt, options)) {
                        // If mongocrypt_t has not yet cached the DEK, supply it.
                        if (MongoCryptContext.State.NEED_MONGO_KEYS == ctx.getState()) {
                            ctx.addMongoOperationResult(keyDocument);
                            ctx.completeMongoOperation();
                        }
                        assert ctx.getState() == MongoCryptContext.State.READY;
                        RawBsonDocument result = ctx.finish();
                        BsonValue encryptedValue = result.get("v");
                        // Create a copy of the binary data with the non-encrypted subtype.
                        BsonBinary notEncryptedValue = new BsonBinary(BsonBinarySubType.BINARY, encryptedValue.asBinary().getData());
                        String key = String.format("key%04d", i);
                        encrypted.append(key, encryptedValue);
                        notEncrypted.append(key, notEncryptedValue);
                    }
                }
            }

            // Decrypt `notEncrypted` to measure baseline. No decryption is expected.
            {
                double medianDurationMicroSeconds = measureMedianDurationOfDecrypt(mongoCrypt, notEncrypted);
                System.out.printf("Baseline median duration (µs)  : %.2f%n", medianDurationMicroSeconds);
                System.out.printf("Baseline expected ops/sec      : %.2f%n", 1_000_000 / medianDurationMicroSeconds);
            }

            // Decrypt `notEncrypted` and measure ops/sec. No decryption is expected.
            {
                long medianOpsPerSec = measureMedianOpsPerSecOfDecrypt(mongoCrypt, notEncrypted);
                System.out.printf("Baseline median ops/sec        : %d%n", medianOpsPerSec);
            }


            // Decrypt `encrypted`.
            {
                double medianDurationMicroSeconds = measureMedianDurationOfDecrypt(mongoCrypt, encrypted);
                System.out.printf("Decrypting median duration (µs): %.2f%n", medianDurationMicroSeconds);
                System.out.printf("Decrypting expected ops/sec:   : %.2f%n", 1_000_000 / medianDurationMicroSeconds);
            }


            // Decrypt `encrypted` and measure ops/sec.
            {
                long medianOpsPerSec = measureMedianOpsPerSecOfDecrypt(mongoCrypt, encrypted);
                System.out.printf("Decrypting median ops/sec      : %d%n", medianOpsPerSec);
            }
        }
    }
}