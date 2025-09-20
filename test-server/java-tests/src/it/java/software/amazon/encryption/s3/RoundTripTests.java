/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.smithy.java.aws.client.restjson.RestJsonClientProtocol;
import software.amazon.smithy.java.client.core.ClientConfig;
import software.amazon.smithy.java.client.core.ClientProtocol;
import software.amazon.smithy.java.client.core.endpoint.EndpointResolver;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.GetObjectInput;
import software.amazon.encryption.s3.model.GetObjectOutput;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.PutObjectInput;
import software.amazon.encryption.s3.model.S3ECConfig;
import software.amazon.encryption.s3.model.S3ECTestServerApiService;
import software.amazon.encryption.s3.model.S3EncryptionClientError;
import software.amazon.smithy.java.http.api.HttpRequest;
import software.amazon.smithy.java.http.api.HttpResponse;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;

public class RoundTripTests {
    private static final String JAVA_V3 = "Java-V3";
    private static final String PYTHON_V3 = "Python-V3";
    private static final String GO_V3 = "Go-V3";
    private static final String NET_V2 = "NET-V2";
    private static final String NET_V3 = "NET-V3";
    private static final String PHP_V2 = "PHP-V2";
    private static final String PHP_V3 = "PHP-V3";
    private static final String RUBY_V2 = "Ruby-V2";
    private static final String RUBY_V3 = "Ruby-V3";
    
    private static final List<LanguageServerTarget> serverList;
    private static final Map<String, LanguageServerTarget> serverMap;

    private static final String KMS_KEY_ARN = System.getenv("TEST_SERVER_KMS_KEY_ARN") != null ?
        System.getenv("TEST_SERVER_KMS_KEY_ARN") : "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Test-Server-Github-KMS-Key";
    private static final Region KMS_REGION = Region.getRegion(Regions.fromName("us-west-2"));
    private static final String BUCKET = System.getenv("TEST_SERVER_S3_BUCKET") != null ? 
        System.getenv("TEST_SERVER_S3_BUCKET") : "s3ec-test-server-github-bucket";

    static {
        serverList = new ArrayList<>(14);
        serverList.add(new LanguageServerTarget(JAVA_V3, "8080"));
        serverList.add(new LanguageServerTarget(PYTHON_V3, "8081"));
        serverList.add(new LanguageServerTarget(GO_V3, "8082"));
        serverList.add(new LanguageServerTarget(NET_V2, "8083"));
        serverList.add(new LanguageServerTarget(NET_V3, "8084"));
        serverList.add(new LanguageServerTarget(PHP_V2, "8087"));
        serverList.add(new LanguageServerTarget(PHP_V3, "8093"));
        serverList.add(new LanguageServerTarget(RUBY_V2, "8086"));
        serverList.add(new LanguageServerTarget(RUBY_V3, "8092"));

        serverMap = new HashMap<>(14);
        serverMap.put(JAVA_V3, new LanguageServerTarget(JAVA_V3, "8080"));
        serverMap.put(PYTHON_V3, new LanguageServerTarget(PYTHON_V3, "8081"));
        serverMap.put(GO_V3, new LanguageServerTarget(GO_V3, "8082"));
        serverMap.put(NET_V2, new LanguageServerTarget(NET_V2, "8083"));
        serverMap.put(NET_V3, new LanguageServerTarget(NET_V3, "8084"));
        serverMap.put(PHP_V2, new LanguageServerTarget(PHP_V2, "8087"));
        serverMap.put(PHP_V3, new LanguageServerTarget(PHP_V3, "8093"));
        serverMap.put(RUBY_V2, new LanguageServerTarget(RUBY_V2, "8086"));
        serverMap.put(RUBY_V3, new LanguageServerTarget(RUBY_V3, "8092"));
    }

    // Encryption context validation behavior varies by implementation:
    // - Go: Does not validate encryption context on decrypt operations
    // - .NET: Only validates against encryption context stored in the object metadata
    // If the encryption context provided to getObject does not match the encryption context on the stored object,
    // these implementations will not raise an error as expected.
    // For now, skip tests that expect encryption context validation on decrypt.
    private static final Set<String> ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED =
        Set.of(GO_V3, PHP_V2, PHP_V3, NET_V2, NET_V3);
    
    // S3EC .NET implementations does not accept encryption context (EC) during putObject operations.
    // These tests are not configured to pass encryption context at client level but at encrypt, 
    // So, for .NET EC is not passed.
    // For now, skip tests that expect encryption context validation on decrypt.
    private static final Set<String> ENCRYPTION_CONTEXT_ON_ENCRYPT_UNSUPPORTED =
        Set.of(NET_V2, NET_V3);

    static public class LanguageServerTarget {
        public String getLanguageName() {
            return languageName;
        }

        public URI getServerURI() {
            return serverURI;
        }

        private final String baseURI = "http://localhost";
        private String languageName;
        private URI serverURI;

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            LanguageServerTarget that = (LanguageServerTarget) o;
            return Objects.equals(languageName, that.languageName) && Objects.equals(serverURI, that.serverURI);
        }

        @Override
        public int hashCode() {
            return Objects.hash(languageName, serverURI);
        }

        LanguageServerTarget(String language, String port) {
            languageName = language;
            serverURI = URI.create(baseURI+ ":" + port);
        }

        @Override
        public String toString() {
            return languageName;
        }
    }

    @BeforeAll
    public static void setup() {
        // Wait for servers to start
        for (LanguageServerTarget server : serverList) {
            if (!serverListening(server.getServerURI())) {
                throw new RuntimeException(String.format("Test Server for %s is not running at endpoint: %s", server.getLanguageName(), server.getServerURI()));
            }
        }
    }

    public static boolean serverListening(URI uri) {
        try (Socket ignored = new Socket(uri.getHost(), uri.getPort())) {
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    static S3ECTestServerClient testServerClientFor(LanguageServerTarget server) {
        S3ECTestServerApiService apiService = S3ECTestServerApiService.instance();
        ClientProtocol<HttpRequest, HttpResponse> rest = new RestJsonClientProtocol(apiService.schema().id());
        return S3ECTestServerClient.builder()
          .endpointResolver(EndpointResolver.staticEndpoint(server.serverURI))
          .withConfiguration(ClientConfig.builder()
            .service(apiService)
            .protocol(rest)
            .endpointResolver(EndpointResolver.staticEndpoint(server.serverURI))
            .build())
          .build();
    }

    static Stream<Arguments> clientsForTest() {
        return serverList.stream()
          .map(LanguageServerTarget::getLanguageName)
          .map(Arguments::of);
    }

    static Stream<Arguments> crossLanguageClients() {
        return serverList.stream()
          .flatMap(t1 -> serverList.stream()
            .flatMap(t2 -> Stream.of(
              Arguments.of(t1, t2)
            )));
    }

    /**
     * Annoyingly, Smithy doesn't provide an interface for map types
     * in HTTP headers, so we have to do the serde ourselves
     * Servers need an equivalent utility.
     * TODO: Move to a utilities class or something.
     */
    private List<String> metadataMapToList(Map<String, String> md) {
        List<String> mdAsList = new ArrayList<>(md.size());
        for (Map.Entry<String, String> keyValue : md.entrySet()) {
            // Using ":" because Smithy will parse "," into a flattened list
            mdAsList.add("[" + keyValue.getKey() + "]:[" + keyValue.getValue() + "]");
        }
        return mdAsList;
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("crossLanguageClients")
    public void crossLanguageTestKms(LanguageServerTarget encLang, LanguageServerTarget decLang) {
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = "cross-lang-test-key-" + encLang;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn).build())
          .build());
        String encS3ECId = encClientOutput.getClientId();
        encClient.putObject(PutObjectInput.builder()
          .clientID(encS3ECId)
          .key(objectKey)
          .bucket(BUCKET)
          .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
          .build());
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn).build())
          .build());
        String decS3ECId = decClientOutput.getClientId();
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
          .clientID(decS3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .build());

        if (!input.equals(StandardCharsets.UTF_8.decode(output.getBody()).toString())) {
            fail(String.format("Encryption in %s failed to decrpyt in %s!", encLang, decLang));
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("crossLanguageClients")
    public void crossLanguageTestKmsWithEncCtx(LanguageServerTarget encLang, LanguageServerTarget decLang) {
        if (ENCRYPTION_CONTEXT_ON_ENCRYPT_UNSUPPORTED.contains(encLang.getLanguageName())) {
            return;
        }
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = "cross-lang-test-key-kms-ec-" + encLang;
        final String input = "simple-test-input";
        final Map<String, String> encCtx = new HashMap<>();
        encCtx.put("user-defined-enc-ctx-key", "user-defined-enc-ctx-value");
        encCtx.put("user-defined-enc-ctx-key-2", "user-defined-enc-ctx-value-2");
        final List<String> mdAsList = metadataMapToList(encCtx);
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn).build())
          .build());
        String encS3ECId = encClientOutput.getClientId();

        encClient.putObject(PutObjectInput.builder()
          .clientID(encS3ECId)
          .key(objectKey)
          .bucket(BUCKET)
          .metadata(mdAsList)
          .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
          .build());
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn).build())
          .build());
        String decS3ECId = decClientOutput.getClientId();
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
          .clientID(decS3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .metadata(mdAsList)
          .build());

        if (!input.equals(StandardCharsets.UTF_8.decode(output.getBody()).toString())) {
            fail(String.format("Encryption in %s failed to decrpyt in %s!", encLang, decLang));
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("crossLanguageClients")
    public void crossLanguageTestKmsWithSubsetEncCtxFails(LanguageServerTarget encLang, LanguageServerTarget decLang) {
        if (ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED.contains(decLang.getLanguageName())) {
            return;
        }
        if (ENCRYPTION_CONTEXT_ON_ENCRYPT_UNSUPPORTED.contains(encLang.getLanguageName())) {
            return;
        }
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = "cross-lang-test-key-kms-ec-subset-fails" + encLang;
        final String input = "simple-test-input";
        final Map<String, String> encCtx = new HashMap<>();
        encCtx.put("user-defined-enc-ctx-key", "user-defined-enc-ctx-value");
        encCtx.put("user-defined-enc-ctx-key-2", "user-defined-enc-ctx-value-2");
        final List<String> mdAsList = metadataMapToList(encCtx);
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn).build())
                .build());
        String encS3ECId = encClientOutput.getClientId();

        encClient.putObject(PutObjectInput.builder()
                .clientID(encS3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .metadata(mdAsList)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn).build())
                .build());
        String decS3ECId = decClientOutput.getClientId();
        try {
            decClient.getObject(GetObjectInput.builder()
                    .clientID(decS3ECId)
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected exception!");
        } catch (S3EncryptionClientError e) {
            if (decLang.languageName.equals(RUBY_V3) || decLang.languageName.equals(RUBY_V2)) {
                assertTrue(e.getMessage().contains("Value of encryption context from envelope does not match the provided encryption context"));
            } else {
                assertTrue(e.getMessage().contains("Provided encryption context does not match information retrieved from S3"));
            }
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("crossLanguageClients")
    public void crossLanguageTestKmsWithIncorrectEncCtxFails(LanguageServerTarget encLang, LanguageServerTarget decLang) {
        if (ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED.contains(decLang.getLanguageName())) {
            return;
        }
        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = "cross-lang-test-key-kms-ec-incorrect-fails" + encLang;
        final String input = "simple-test-input";
        final Map<String, String> encCtx = new HashMap<>();
        encCtx.put("user-defined-enc-ctx-key", "user-defined-enc-ctx-value");
        encCtx.put("user-defined-enc-ctx-key-2", "user-defined-enc-ctx-value-2");
        final List<String> mdAsList = metadataMapToList(encCtx);
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn).build())
          .build());
        String encS3ECId = encClientOutput.getClientId();

        encClient.putObject(PutObjectInput.builder()
          .clientID(encS3ECId)
          .key(objectKey)
          .bucket(BUCKET)
          .metadata(mdAsList)
          .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
          .build());
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn).build())
          .build());
        String decS3ECId = decClientOutput.getClientId();

        final Map<String, String> incorrectEncCtx = new HashMap<>();
        incorrectEncCtx.put("this-is-wrong-ec-key", "bad-value");
        var incorrectMdAsList = metadataMapToList(incorrectEncCtx);
        try {
            decClient.getObject(GetObjectInput.builder()
              .clientID(decS3ECId)
              .bucket(BUCKET)
              .key(objectKey)
              .metadata(incorrectMdAsList)
              .build());
            fail("Expected exception!");
        } catch (S3EncryptionClientError e) {
            if (decLang.languageName.equals(RUBY_V3) || decLang.languageName.equals(RUBY_V2)) {
              assertTrue(e.getMessage().contains("Value of encryption context from envelope does not match the provided encryption context"));
            } else {
              assertTrue(e.getMessage().contains("Provided encryption context does not match information retrieved from S3"));
            }
        }
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: Java, Decrypt: {0}")
    @MethodSource("clientsForTest")
    public void kmsV1Legacy(String language) {
        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "test-key-kms-v1-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .enableLegacyWrappingAlgorithms(true)
            .keyMaterial(kmsKeyArn)
            .build())
          .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client
        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
          new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
            .withStorageMode(CryptoStorageMode.ObjectMetadata)
            .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
          .withCryptoConfiguration(v1Config)
          .withEncryptionMaterials(materialsProvider)
          .build();

        v1Client.putObject(BUCKET, objectKey, input);

        GetObjectOutput output = client.getObject(GetObjectInput.builder()
          .clientID(s3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: Java, Decrypt: {0}")
    @MethodSource("clientsForTest")
    public void kmsV1LegacyWithEncCtx(String language) {
        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "test-key-kms-v1-with-enc-ctx-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .enableLegacyWrappingAlgorithms(true)
            .keyMaterial(kmsKeyArn)
            .build())
          .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client
        // V1 Client
        final String ecKey = "user-metadata-key";
        final String ecValue = "user-metadata-value-v1";
        KMSEncryptionMaterials kmsMaterials = new KMSEncryptionMaterials(KMS_KEY_ARN);
        kmsMaterials.addDescription(ecKey, ecValue);
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(kmsMaterials);

        CryptoConfiguration v1Config =
          new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
            .withStorageMode(CryptoStorageMode.ObjectMetadata)
            .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
          .withCryptoConfiguration(v1Config)
          .withEncryptionMaterials(materialsProvider)
          .build();

        v1Client.putObject(BUCKET, objectKey, input);

        final Map<String, String> encCtx = new HashMap<>();
        encCtx.put(ecKey, ecValue);
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
          .clientID(s3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .metadata(metadataMapToList(encCtx))
          .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    @ParameterizedTest(name = "{displayName} for Encrypt: Java, Decrypt: {0}")
    @MethodSource("clientsForTest")
    public void kmsV1LegacyFailsWhenLegacyDisabled(String language) {
        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "test-key-kms-v1-fails-disabled" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .enableLegacyWrappingAlgorithms(false)
            .keyMaterial(kmsKeyArn)
            .build())
          .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client
        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
          new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
            .withStorageMode(CryptoStorageMode.ObjectMetadata)
            .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
          .withCryptoConfiguration(v1Config)
          .withEncryptionMaterials(materialsProvider)
          .build();

        v1Client.putObject(BUCKET, objectKey, input);

        try {
            client.getObject(GetObjectInput.builder()
              .clientID(s3ECId)
              .bucket(BUCKET)
              .key(objectKey)
              .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            if (language.equals(NET_V3) || language.equals(NET_V2)) {
              assertTrue(e.getMessage().contains(
                "The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration V2."
              ));
            } else if (language.equals(RUBY_V3) || language.equals(RUBY_V2)) {
              assertTrue(e.getMessage().contains("The requested object is encrypted with V1 encryption schemas that have been disabled by client configuration security_profile = :v2. Retry with :v2_and_legacy or re-encrypt the object."));
            } else {
              assertTrue(e.getMessage().contains("Enable legacy wrapping algorithms to use legacy key wrapping algorithm: kms"));
            }
        }
    }

}
