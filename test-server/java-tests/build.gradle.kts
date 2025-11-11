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
        
        // Optimize test execution for performance
        maxParallelForks = Runtime.getRuntime().availableProcessors()
        forkEvery = 100
        
        // JVM optimizations for faster test execution
        jvmArgs = listOf(
            "-XX:+UseG1GC",
            "-XX:MaxGCPauseMillis=100",
            "-Xmx2g",
            "-XX:+TieredCompilation",
            "-XX:TieredStopAtLevel=1"
        )
        
        // Passing information from Gradle into the tests so that we can filter our servers
        systemProperty("test.filter.servers", System.getProperty("test.filter.servers"))
        
        // Disable AWS SDK v1 deprecation warnings for cleaner output
        systemProperty("aws.java.v1.disableDeprecationAnnouncement", "true")
        
        // For debugging (uncomment if needed)
        // testLogging {
        //     events("passed", "skipped", "failed", "standardOut", "standardError")
        //     showStandardStreams = true
        // }
    }
}

repositories {
    mavenLocal()
    mavenCentral()
}
