plugins {
    `java-library`
    id("software.amazon.smithy.gradle.smithy-base")
    application
}

// Dynamically read S3EC version from submodule's pom.xml
val s3ecVersion = file("s3ec-staging/pom.xml").readText()
    .let { Regex("<version>(.*?)</version>").find(it)?.groupValues?.get(1) ?: "4.0.0" }

dependencies {
    val smithyJavaVersion: String by project

    smithyBuild("software.amazon.smithy.java:plugins:$smithyJavaVersion")

    implementation("software.amazon.smithy:smithy-rules-engine:1.59.0")
    implementation("software.amazon.smithy.java:server-netty:$smithyJavaVersion")
    implementation("software.amazon.smithy.java:aws-server-restjson:$smithyJavaVersion")

    // S3EC from local Maven repository (installed by mvn install)
    // Version is dynamically read from s3ec-staging/pom.xml
    implementation("software.amazon.encryption.s3:amazon-s3-encryption-client-java:$s3ecVersion")
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
