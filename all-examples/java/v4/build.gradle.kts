plugins {
    java
    application
}

group = "software.amazon.encryption.s3.example"
version = "1.0.0"

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    // AWS SDK v2 dependencies
    implementation(platform("software.amazon.awssdk:bom:2.20.0"))
    implementation("software.amazon.awssdk:s3")
    implementation("software.amazon.awssdk:kms")
    implementation("software.amazon.awssdk:auth")
    
    // S3 Encryption Client v4 from local Maven repository
    implementation("software.amazon.encryption.s3:amazon-s3-encryption-client-java:3.6.0")
}

application {
    mainClass.set("software.amazon.encryption.s3.example.Main")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "software.amazon.encryption.s3.example.Main"
    }
    
    // Create a fat jar with all dependencies
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    archiveBaseName.set("s3ec-java-v4-example")
}

tasks.named<JavaExec>("run") {
    standardInput = System.`in`
}
