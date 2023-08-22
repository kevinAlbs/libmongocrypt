plugins {
    id("application")
}

application {
    mainClass.set("com.mongodb.crypt.benchmark.BenchmarkRunner")
}

dependencies {
    implementation(project(":")) // Reference to the parent project
}
