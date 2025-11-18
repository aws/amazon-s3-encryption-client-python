plugins {
    `java-library`
    id("software.amazon.smithy.gradle.smithy-base")
}

dependencies {
    val smithyJavaVersion: String by project

    smithyBuild("software.amazon.smithy.java:plugins:$smithyJavaVersion")
    implementation("software.amazon.smithy:smithy-rules-engine:1.59.0")

    // Client dependencies
    implementation("software.amazon.smithy.java:aws-client-restjson:$smithyJavaVersion")
    implementation("software.amazon.smithy.java:client-core:$smithyJavaVersion")

    // Test dependencies
    testImplementation("org.junit.jupiter:junit-jupiter:5.13.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    // JUnit Suite support for test ordering
    testImplementation("org.junit.platform:junit-platform-suite-api:1.10.0")
    testRuntimeOnly("org.junit.platform:junit-platform-suite-engine:1.10.0")
    testImplementation("com.amazonaws:aws-java-sdk:1.12.788")
    testImplementation("software.amazon.awssdk:s3:2.37.1")
    testImplementation("org.bouncycastle:bcprov-jdk15on:1.70")
}

// Add generated Java sources to the main sourceset
afterEvaluate {
    val clientPath = smithy.getPluginProjectionPath(smithy.sourceProjection.get(), "java-client-codegen")
    sourceSets {
        main {
            java {
                srcDir(clientPath)
            }
        }
        create("it") {
            compileClasspath += main.get().output + configurations["testRuntimeClasspath"] + configurations["testCompileClasspath"]
            runtimeClasspath += output + compileClasspath + test.get().runtimeClasspath + test.get().output
        }
    }
}

tasks {
    val smithyBuild by getting
    compileJava {
        dependsOn(smithyBuild)
    }

    val integ by registering(Test::class) {
        useJUnitPlatform()
        testClassesDirs = sourceSets["it"].output.classesDirs
        classpath = sourceSets["it"].runtimeClasspath
        outputs.upToDateWhen { false }
        outputs.cacheIf { false }
        
        // Enable parallel test execution
        systemProperty("junit.jupiter.execution.parallel.enabled", "true")
        systemProperty("junit.jupiter.execution.parallel.mode.default", "concurrent")
        systemProperty("junit.jupiter.execution.parallel.mode.classes.default", "concurrent")
        // Configure thread pool size - adjust based on I/O-bound nature of tests
        systemProperty("junit.jupiter.execution.parallel.config.strategy", "fixed")
        maxParallelForks = 1  // One JVM
        systemProperty("junit.jupiter.execution.parallel.config.fixed.parallelism", 
            Runtime.getRuntime().availableProcessors().toString())  // Scale with CPU
        
        // Passing information from Gradle into the tests so that we can filter our servers
        systemProperty("test.filter.servers", System.getProperty("test.filter.servers"))
        // For debugging
        // // Enable System.out output
        // testLogging {
        //     events("passed", "skipped", "failed", "standardOut", "standardError")
        //     showStandardStreams = true
        // }

        // // Disable AWS SDK v1 deprecation warnings
        // systemProperty("aws.java.v1.disableDeprecationAnnouncement", "true")
    }
}

repositories {
    mavenLocal()
    mavenCentral()
}
