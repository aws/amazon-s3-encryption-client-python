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
import software.amazon.encryption.s3.model.*;
import software.amazon.smithy.java.aws.client.restjson.RestJsonClientProtocol;
import software.amazon.smithy.java.client.core.ClientConfig;
import software.amazon.smithy.java.client.core.ClientProtocol;
import software.amazon.smithy.java.client.core.endpoint.EndpointResolver;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
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
    private static final List<LanguageServerTarget> serverList;
    private static final Map<String, LanguageServerTarget> serverMap;

    private static final String KMS_KEY_ARN = System.getenv("TEST_SERVER_KMS_KEY_ARN") != null ?
        System.getenv("TEST_SERVER_KMS_KEY_ARN") : "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Test-Server-Github-KMS-Key";
    private static final Region KMS_REGION = Region.getRegion(Regions.fromName("us-west-2"));
    private static final String BUCKET = System.getenv("TEST_SERVER_S3_BUCKET") != null ? 
        System.getenv("TEST_SERVER_S3_BUCKET") : "s3ec-test-server-github-bucket";

    // Strings for naming each version
    // Each language can have up to 3 versions:
    // vN-Current: Currently released version. Does not support setting commitment policy.
    // vN-Transition: Proposed patch/feature release version with a new client class.
    //      Supports setting commitment policy; no default policy; MUST be explicitly configured on constructor.
    // vN+1: Proposed breaking release version.
    //      Supports setting commitment policy; defaults to `RequireEncryptRequireDecrypt`.

    private static final String JAVA_V3_CURRENT = "Java-V3-Current";
    private static final String JAVA_V3_TRANSITION = "Java-V3-Transition";
    private static final String JAVA_V4 = "Java-V4";

    // No Python S3EC versions are released. Only test V3 as the "vN+1" version.
    private static final String PYTHON_V3 = "Python-V3";

    private static final String GO_V3_CURRENT = "Go-V3-Current";
    private static final String GO_V3_TRANSITION = "Go-V3-Transition";
    private static final String GO_V4 = "Go-V4";

    private static final String NET_V2_CURRENT = "Net-V2-Current";
    private static final String NET_V2_TRANSITION = "Net-V2-Transition";
    private static final String NET_V3 = "Net-V3";

    private static final String CPP_V2_CURRENT = "Cpp-V2-Current";
    private static final String CPP_V2_TRANSITION = "Cpp-V2-Transition";
    private static final String CPP_V3 = "Cpp-V3";

    private static final String RUBY_V2_CURRENT = "Ruby-V2-Current";
    private static final String RUBY_V2_TRANSITION = "Ruby-V2-Transition";
    private static final String RUBY_V3 = "Ruby-V3";

    private static final String PHP_V2_CURRENT = "PHP-V2-Current";
    private static final String PHP_V2_TRANSITION = "PHP-V2-Transition";
    private static final String PHP_V3 = "PHP-V3";

    static {
        serverList = new ArrayList<>(14);
        serverList.add(new LanguageServerTarget("Java-V3", "8080"));
        serverList.add(new LanguageServerTarget("Python-V3", "8081"));
        serverList.add(new LanguageServerTarget("Go-V3", "8082"));

        serverMap = new HashMap<>(14);
        serverMap.put("Java-V3", new LanguageServerTarget("Java-V3", "8080"));
        serverMap.put("Python-V3", new LanguageServerTarget("Python-V3", "8081"));
        serverMap.put("Go-V3", new LanguageServerTarget("Go-V3", "8082"));
    }

    // These S3EC implementations do not validate encryption context provided to getObject (i.e. on decrypt).
    // If the encryption context provided to getObject does not match the encryption context on the stored object,
    // these implementations will not raise an error as expected.
    // For now, skip tests that expect encryption context validation on decrypt.
    private static final Set<String> ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED =
        Set.of("Go-V3");

    private static final Set<String> CURRENT_VERSIONS =
        Set.of(
            JAVA_V3_CURRENT,
            GO_V3_CURRENT,
            NET_V2_CURRENT,
            CPP_V2_CURRENT,
            RUBY_V2_CURRENT,
            PHP_V2_CURRENT
        );

    private static final Set<String> TRANSITION_VERSIONS =
        Set.of(
            JAVA_V3_TRANSITION,
            GO_V3_TRANSITION,
            NET_V2_TRANSITION,
            CPP_V2_TRANSITION,
            RUBY_V2_TRANSITION,
            PHP_V2_TRANSITION
        );

    private static final Set<String> IMPROVED_VERSIONS =
        Set.of(
            JAVA_V4,
            PYTHON_V3,
            GO_V4,
            NET_V3,
            CPP_V3,
            RUBY_V3,
            PHP_V3
        );

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

    static Stream<Arguments> currentClientsForTest() {
        return clientsForTest()
          .filter(arg -> CURRENT_VERSIONS.contains(arg.get()[0]));
    }


    static Stream<Arguments> transitionClientsForTest() {
        return clientsForTest()
          .filter(arg -> TRANSITION_VERSIONS.contains(arg.get()[0]));
    }


    static Stream<Arguments> improvedClientsForTest() {
        return clientsForTest()
          .filter(arg -> IMPROVED_VERSIONS.contains(arg.get()[0]));
    }

    static Stream<Arguments> crossLanguageClients() {
        return serverList.stream()
          .flatMap(t1 -> serverList.stream()
            .flatMap(t2 -> Stream.of(
              Arguments.of(t1, t2)
            )));
    }

    static Stream<Arguments> crossLanguageClientsWithAlgSuite() {
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
            assertTrue(e.getMessage().contains("Provided encryption context does not match information retrieved from S3"));
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
            assertTrue(e.getMessage().contains("Provided encryption context does not match information retrieved from S3"));
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
            assertTrue(e.getMessage().contains("Enable legacy wrapping algorithms to use legacy key wrapping algorithm: kms"));
        }
    }

    // Begin Exhaustive tests defined here:
    // https://tiny.amazon.com/3xnzwczl/loopcloumicrpeyJ3
    

    // Exhaustive test 1
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Current	Decrypt	null	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("crossLanguageClients")
    public void GIVEN_DataEncryptedWithKC_AND_CurrentClientDecrypting_WHEN_Decrypt_THEN_Fail(LanguageServerTarget encLang, LanguageServerTarget decLang) {
        // Given: encrypt language is either an improved version or a transition version
        if (!IMPROVED_VERSIONS.contains(encLang.getLanguageName()) || !TRANSITION_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is a current version
        if (!CURRENT_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-decrypt-current-test-key-" + encLang;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
          .kmsKeyId(KMS_KEY_ARN)
          .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn)
            .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .build())
          .build());
        String encS3ECId = encClientOutput.getClientId();
        // Given: object encrypted with key commitment
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

        // Then: Fails
        try {
            decClient.getObject(GetObjectInput.builder()
              .clientID(decS3ECId)
              .bucket(BUCKET)
              .key(objectKey)
              .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting unrecognized alg suite"));
        }
    }

    // Exhaustive test 2
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	ForbidEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1, Decrypt: {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
      LanguageServerTarget language
    ) {
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

        S3ECTestServerClient decClient = testServerClientFor(language);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
          .config(S3ECConfig.builder()
            .keyMaterial(kmsKeyArn).build())
          .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC object with a current version client
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
          .clientID(decS3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .build());

        // Then: Pass
        client.getObject(GetObjectInput.builder()
          .clientID(s3ECId)
          .bucket(BUCKET)
          .key(objectKey)
          .build());
    }

    // HERE
    // Exhaustive test 3
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	ForbidEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            String language
    ) {
        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "test-key-kms-v1-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with GCM encryption
        // V1 Client with GCM
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption) // StrictAuthenticatedEncryption uses GCM
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt GCM object with an improved version client
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 4
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	ForbidEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientDecryptingWithForbidEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            LanguageServerTarget encLang, LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version or a transition version
        if (!IMPROVED_VERSIONS.contains(encLang.getLanguageName()) || !TRANSITION_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-improved-test-key-" + encLang;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String encS3ECId = encClientOutput.getClientId();
        
        // Given: object encrypted with key commitment
        encClient.putObject(PutObjectInput.builder()
                .clientID(encS3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());
                
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC-GCM object with an improved version client with ForbidEncryptAllowDecrypt policy
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }


    // Exhaustive test 5
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Decrypt	null	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-CBC, Decrypt: {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientDecryptingWithNullPolicy_WHEN_Decrypt_THEN_Fail(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "test-key-kms-v1-cbc-null-policy-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with CBC encryption
        // V1 Client with CBC
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption) // AuthenticatedEncryption uses CBC
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt CBC object with an improved version client with null policy
        // Then: Fails
        try {
            client.getObject(GetObjectInput.builder()
                    .clientID(s3ECId)
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting with null policy"));
        }
    }

    // Exhaustive test 6
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Decrypt	null	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientDecryptingWithNullPolicy_WHEN_Decrypt_THEN_Fail(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "test-key-kms-v1-gcm-null-policy-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with GCM encryption
        // V1 Client with GCM
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption) // StrictAuthenticatedEncryption uses GCM
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt GCM object with an improved version client with null policy
        // Then: Fails
        try {
            client.getObject(GetObjectInput.builder()
                    .clientID(s3ECId)
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting with null policy"));
        }
    }

    // Exhaustive test 7
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	null	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientDecryptingWithNullPolicy_WHEN_Decrypt_THEN_Pass(
            LanguageServerTarget encLang, LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-improved-null-policy-" + encLang;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String encS3ECId = encClientOutput.getClientId();
        
        // Given: object encrypted with key commitment
        encClient.putObject(PutObjectInput.builder()
                .clientID(encS3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());
                
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC-GCM object with an improved version client with null policy
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }


    // Exhaustive test 8
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	RequireEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-CBC, Decrypt: {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "test-key-kms-v1-cbc-require-encrypt-allow-decrypt-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with CBC encryption
        // V1 Client with CBC
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption) // AuthenticatedEncryption uses CBC
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt CBC object with an improved version client with RequireEncryptAllowDecrypt policy
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 9
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	RequireEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "test-key-kms-v1-gcm-require-encrypt-allow-decrypt-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with GCM encryption
        // V1 Client with GCM
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption) // StrictAuthenticatedEncryption uses GCM
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt GCM object with an improved version client with RequireEncryptAllowDecrypt policy
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 10
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	RequireEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptAllowDecrypt_WHEN_Decrypt_THEN_Pass(
            LanguageServerTarget encLang, LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-improved-require-encrypt-allow-decrypt-" + encLang;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String encS3ECId = encClientOutput.getClientId();
        
        // Given: object encrypted with key commitment
        encClient.putObject(PutObjectInput.builder()
                .clientID(encS3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());
                
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC-GCM object with an improved version client with RequireEncryptAllowDecrypt policy
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }


    // Exhaustive test 11
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Decrypt	RequireEncryptRequireDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-CBC, Decrypt: {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptRequireDecrypt_WHEN_Decrypt_THEN_Fail(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "test-key-kms-v1-cbc-require-encrypt-require-decrypt-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with CBC encryption
        // V1 Client with CBC
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption) // AuthenticatedEncryption uses CBC
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt CBC object with an improved version client with RequireEncryptRequireDecrypt policy
        // Then: Fails
        try {
            client.getObject(GetObjectInput.builder()
                    .clientID(s3ECId)
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting with RequireEncryptRequireDecrypt policy"));
        }
    }

    // Exhaustive test 12
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Decrypt	RequireEncryptRequireDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: Java-V1-GCM, Decrypt: {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptRequireDecrypt_WHEN_Decrypt_THEN_Fail(
            String language
    ) {
        // Given: decrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "test-key-kms-v1-gcm-require-encrypt-require-decrypt-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create the object using the old client with GCM encryption
        // V1 Client with GCM
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ARN);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption) // StrictAuthenticatedEncryption uses GCM
                        .withStorageMode(CryptoStorageMode.ObjectMetadata)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        v1Client.putObject(BUCKET, objectKey, input);

        // When: decrypt GCM object with an improved version client with RequireEncryptRequireDecrypt policy
        // Then: Fails
        try {
            client.getObject(GetObjectInput.builder()
                    .clientID(s3ECId)
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for decrypting with RequireEncryptRequireDecrypt policy"));
        }
    }

    // Exhaustive test 13
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Decrypt	RequireEncryptRequireDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for Encrypt: {0}, Decrypt: {1}")
    @MethodSource("crossLanguageClients")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientDecryptingWithRequireEncryptRequireDecrypt_WHEN_Decrypt_THEN_Pass(
            LanguageServerTarget encLang, LanguageServerTarget decLang
    ) {
        // Given: encrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(encLang.getLanguageName())) {
            return;
        }

        // Given: decrypt language is an improved version
        if (!IMPROVED_VERSIONS.contains(decLang.getLanguageName())) {
            return;
        }

        S3ECTestServerClient encClient = testServerClientFor(encLang);
        final String objectKey = "encrypt-kc-gcm-decrypt-improved-require-encrypt-require-decrypt-" + encLang;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        CreateClientOutput encClientOutput = encClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String encS3ECId = encClientOutput.getClientId();
        
        // Given: object encrypted with key commitment
        encClient.putObject(PutObjectInput.builder()
                .clientID(encS3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());
                
        S3ECTestServerClient decClient = testServerClientFor(decLang);
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput decClientOutput = decClient.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String decS3ECId = decClientOutput.getClientId();

        // When: decrypt KC-GCM object with an improved version client with RequireEncryptRequireDecrypt policy
        GetObjectOutput output = decClient.getObject(GetObjectInput.builder()
                .clientID(decS3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Then: Pass
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 14
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Encrypt	ForbidEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithForbidEncryptAllowDecrypt_WHEN_EncryptWithCBC_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-forbid-encrypt-allow-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with ForbidEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with CBC using an improved version client with ForbidEncryptAllowDecrypt policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 15
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Encrypt	ForbidEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithForbidEncryptAllowDecrypt_WHEN_EncryptWithGCM_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-forbid-encrypt-allow-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with ForbidEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with GCM using an improved version client with ForbidEncryptAllowDecrypt policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 16
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	ForbidEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithForbidEncryptAllowDecrypt_WHEN_EncryptWithKCGCM_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-forbid-encrypt-allow-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with ForbidEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with KC-GCM using an improved version client with ForbidEncryptAllowDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with ForbidEncryptAllowDecrypt policy"));
        }
    }

    // Exhaustive test 17
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	null	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithNullPolicy_WHEN_EncryptWithCBC_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-null-policy-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with CBC using an improved version client with null policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with null policy"));
        }
    }

    // Exhaustive test 18
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	null	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithNullPolicy_WHEN_EncryptWithGCM_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-null-policy-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with GCM using an improved version client with null policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with null policy"));
        }
    }

    // Exhaustive test 19
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Encrypt	null	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithNullPolicy_WHEN_EncryptWithKCGCM_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-null-policy-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with null commitment policy (not explicitly set)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with KC-GCM using an improved version client with null policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 20
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	RequireEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptAllowDecrypt_WHEN_EncryptWithCBC_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-require-encrypt-allow-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with CBC using an improved version client with RequireEncryptAllowDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with RequireEncryptAllowDecrypt policy"));
        }
    }

    // Exhaustive test 21
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	RequireEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptAllowDecrypt_WHEN_EncryptWithGCM_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-require-encrypt-allow-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with GCM using an improved version client with RequireEncryptAllowDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with RequireEncryptAllowDecrypt policy"));
        }
    }

    // Exhaustive test 22
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Encrypt	RequireEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptAllowDecrypt_WHEN_EncryptWithKCGCM_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-require-encrypt-allow-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptAllowDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with KC-GCM using an improved version client with RequireEncryptAllowDecrypt policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 23
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	RequireEncryptRequireDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptRequireDecrypt_WHEN_EncryptWithCBC_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-require-encrypt-require-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with CBC using an improved version client with RequireEncryptRequireDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with RequireEncryptRequireDecrypt policy"));
        }
    }

    // Exhaustive test 24
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	Encrypt	RequireEncryptRequireDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptRequireDecrypt_WHEN_EncryptWithGCM_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-require-encrypt-require-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .enableLegacyWrappingAlgorithms(true)
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: attempt to encrypt with GCM using an improved version client with RequireEncryptRequireDecrypt policy
        // Then: Fails
        try {
            client.putObject(PutObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                    .build());
            fail("Expected Exception");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("TODO: Expected error message for encrypting with RequireEncryptRequireDecrypt policy"));
        }
    }

    // Exhaustive test 25
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	Encrypt	RequireEncryptRequireDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_ImprovedClientEncryptingWithRequireEncryptRequireDecrypt_WHEN_EncryptWithKCGCM_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "encrypt-improved-require-encrypt-require-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();
        
        // Create client with RequireEncryptRequireDecrypt commitment policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // When: encrypt with KC-GCM using an improved version client with RequireEncryptRequireDecrypt policy
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Then: Pass - verify we can decrypt the object
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        assertEquals(input, new String(output.getBody().array()));
    }

    // Exhaustive test 26
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	null	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientReEncryptingWithNullPolicy_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-null-policy-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with null policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        // No commitment policy set - defaults to null
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with CBC encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with null policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with null policy");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Commitment policy cannot be null for re-encryption operations"));
        }
    }

    // Exhaustive test 27
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	null	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientReEncryptingWithNullPolicy_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-null-policy-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with GCM encryption (null policy)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with null policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with null policy");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Commitment policy cannot be null for re-encryption operations"));
        }
    }

    // Exhaustive test 28
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	ReEncrypt	null	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientReEncryptingWithNullPolicy_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-null-policy-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with KC-GCM encryption (null policy)
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with KC-GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with null policy (should allow since existing encryption is KC-GCM)
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }


    // Exhaustive test 29
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	ReEncrypt	ForbidEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientReEncryptingWithForbidEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-forbid-encrypt-allow-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with ForbidEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with CBC encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with ForbidEncryptAllowDecrypt policy
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 30
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	ReEncrypt	ForbidEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientReEncryptingWithForbidEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-forbid-encrypt-allow-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with GCM encryption and ForbidEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with ForbidEncryptAllowDecrypt policy
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 31
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	ForbidEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientReEncryptingWithForbidEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-forbid-encrypt-allow-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with KC-GCM encryption and ForbidEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with KC-GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with ForbidEncryptAllowDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with ForbidEncryptAllowDecrypt policy");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Re-encryption with ForbidEncryptAllowDecrypt policy is not allowed"));
        }
    }

    // Exhaustive test 32
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	RequireEncryptAllowDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-allow-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with RequireEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with CBC encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with RequireEncryptAllowDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with RequireEncryptAllowDecrypt policy on CBC");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Re-encryption with RequireEncryptAllowDecrypt policy requires key commitment"));
        }
    }

    // Exhaustive test 33
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	RequireEncryptAllowDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-allow-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with GCM encryption and RequireEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with RequireEncryptAllowDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with RequireEncryptAllowDecrypt policy on GCM");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Re-encryption with RequireEncryptAllowDecrypt policy requires key commitment"));
        }
    }

    // Exhaustive test 34
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	ReEncrypt	RequireEncryptAllowDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptAllowDecrypt_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-allow-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with KC-GCM encryption and RequireEncryptAllowDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with KC-GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with RequireEncryptAllowDecrypt policy
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

    // Exhaustive test 35
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	RequireEncryptRequireDecrypt	CBC	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_CBCEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptRequireDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-require-decrypt-cbc-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with RequireEncryptRequireDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with CBC encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with RequireEncryptRequireDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with RequireEncryptRequireDecrypt policy on CBC");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Re-encryption with RequireEncryptRequireDecrypt policy requires key commitment"));
        }
    }

    // Exhaustive test 36
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Fail	Improved	ReEncrypt	RequireEncryptRequireDecrypt	GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_GCMEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptRequireDecrypt_WHEN_ReEncrypt_THEN_Fail(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-require-decrypt-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with GCM encryption and RequireEncryptRequireDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .cryptoMode(CryptoMode.StrictAuthenticatedEncryption) // GCM
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Attempt to re-encrypt with RequireEncryptRequireDecrypt policy
        try {
            client.reEncryptObject(ReEncryptObjectInput.builder()
                    .clientID(s3ECId)
                    .key(objectKey)
                    .bucket(BUCKET)
                    .build());
            fail("Expected re-encrypt to fail with RequireEncryptRequireDecrypt policy on GCM");
        } catch (S3EncryptionClientError e) {
            assertTrue(e.getMessage().contains("Re-encryption with RequireEncryptRequireDecrypt policy requires key commitment"));
        }
    }

    // Exhaustive test 37
    // Outcome	Version	Operation	Policy	Content Encryption	
    // Pass	Improved	ReEncrypt	RequireEncryptRequireDecrypt	KC-GCM	

    @ParameterizedTest(name = "{displayName} for {0}")
    @MethodSource("improvedClientsForTest")
    public void GIVEN_KCGCMEncryptedData_AND_ImprovedClientReEncryptingWithRequireEncryptRequireDecrypt_WHEN_ReEncrypt_THEN_Pass(
            String language
    ) {
        // Given: language is an improved version
        if (!IMPROVED_VERSIONS.contains(language)) {
            return;
        }

        S3ECTestServerClient client = testServerClientFor(serverMap.get(language));
        final String objectKey = "reencrypt-improved-require-encrypt-require-decrypt-kc-gcm-" + language;
        final String input = "simple-test-input";
        KeyMaterial kmsKeyArn = KeyMaterial.builder()
                .kmsKeyId(KMS_KEY_ARN)
                .build();

        // Create client with KC-GCM encryption and RequireEncryptRequireDecrypt policy
        CreateClientOutput output1 = client.createClient(CreateClientInput.builder()
                .config(S3ECConfig.builder()
                        .keyMaterial(kmsKeyArn)
                        .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                        .build())
                .build());
        String s3ECId = output1.getClientId();

        // Create object with KC-GCM encryption
        client.putObject(PutObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .body(ByteBuffer.wrap(input.getBytes(StandardCharsets.UTF_8)))
                .build());

        // Re-encrypt with RequireEncryptRequireDecrypt policy
        client.reEncryptObject(ReEncryptObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .build());

        // Verify decryption still works
        GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(s3ECId)
                .key(objectKey)
                .bucket(BUCKET)
                .build());
        assertEquals(input, StandardCharsets.UTF_8.decode(output.getBody()).toString());
    }

}
