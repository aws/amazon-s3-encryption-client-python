plugins {
    `java-library`
    application
}

dependencies {
    // S3 Encryption Client Java v3
    implementation("software.amazon.encryption.s3:amazon-s3-encryption-client-java:3.5.0")
    
    // AWS SDK dependencies
    implementation("software.amazon.awssdk:s3:2.31.66")
    implementation("software.amazon.awssdk:kms:2.31.66")
    implementation("software.amazon.awssdk:core:2.31.66")
}

application {
    mainClass = "com.example.S3EncryptionExample"
}

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}
