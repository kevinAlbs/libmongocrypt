package com.mongodb.crypt.benchmark;
import com.mongodb.crypt.capi.CAPI;

public class BenchmarkRunner {
    public static void main(String[] args) {
        System.out.println ("BenchmarkRunner got libmongocrypt version: " + CAPI.mongocrypt_version(null).toString());
    }
}