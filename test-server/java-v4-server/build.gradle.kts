plugins {
    `java-library`
    id("software.amazon.smithy.gradle.smithy-base")
    application
}

dependencies {
    val smithyJavaVersion: String by project

    smithyBuild("software.amazon.smithy.java:plugins:$smithyJavaVersion")

    implementation("software.amazon.smithy:smithy-rules-engine:1.59.0")
    implementation("software.amazon.smithy.java:server-netty:$smithyJavaVersion")
    implementation("software.amazon.smithy.java:aws-server-restjson:$smithyJavaVersion")

    // S3EC from local Maven repository (installed by mvn install)
    implementation("software.amazon.encryption.s3:amazon-s3-encryption-client-java:3.4.0-add-kc")
}

// Use that application plugin to start the service via the `run` task.
application {
    mainClass = "software.amazon.encryption.s3.S3ECJavaTestServer"
}

// Add generated Java files to the main sourceSet
afterEvaluate {
    val serverPath = smithy.getPluginProjectionPath(smithy.sourceProjection.get(), "java-server-codegen")
    sourceSets {
        main {
            java {
                srcDir(serverPath)
            }
        }
    }
}

tasks {
    compileJava {
        dependsOn(smithyBuild)
    }
}

// Helps Intellij IDE's discover smithy models
sourceSets {
    main {
        java {
            srcDir("../model")
        }
    }
}

repositories {
    mavenLocal()
    mavenCentral()
}
