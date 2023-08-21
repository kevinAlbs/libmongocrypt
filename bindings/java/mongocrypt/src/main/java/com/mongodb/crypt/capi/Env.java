package com.mongodb.crypt.capi;

public class Env {
    public static boolean VERBOSE;
    public static boolean REUSE_JAVA_CRYPTO_INSTANCES;
    public static boolean USE_BINARY_DEFINITION;

    public static void init() {
        if (System.getenv("VERBOSE") != null && System.getenv("VERBOSE").equals("ON")) {
            Env.VERBOSE = true;
        }
        if (System.getenv("REUSE_JAVA_CRYPTO_INSTANCES") != null && System.getenv("REUSE_JAVA_CRYPTO_INSTANCES").equals("ON")) {
            Env.REUSE_JAVA_CRYPTO_INSTANCES = true;
            throw new RuntimeException ("REUSE_JAVA_CRYPTO_INSTANCES is not yet implemented on this branch");
        }
        if (System.getenv("USE_BINARY_DEFINITION") != null && System.getenv("USE_BINARY_DEFINITION").equals("ON")) {
            Env.USE_BINARY_DEFINITION = true;
        }
    }

    public static void print() {
        System.out.println ("mongodb-crypt: VERBOSE=" + Env.VERBOSE);
        // System.out.println ("mongodb-crypt: REUSE_JAVA_CRYPTO_INSTANCES=" + Env.REUSE_JAVA_CRYPTO_INSTANCES);
        System.out.println ("mongodb-crypt: USE_BINARY_DEFINITION=" + Env.USE_BINARY_DEFINITION);
    }
}
