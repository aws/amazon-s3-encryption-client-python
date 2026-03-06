/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.amazonaws.services.s3.model.S3Object;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ObjectMetadata;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.junit.jupiter.params.provider.Arguments;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.GetObjectInput;
import software.amazon.encryption.s3.model.GetObjectOutput;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.PutObjectInput;
import software.amazon.encryption.s3.model.PutObjectOutput;
import software.amazon.encryption.s3.model.S3ECConfig;
import software.amazon.encryption.s3.model.S3EncryptionClientError;
import software.amazon.smithy.java.aws.client.restjson.RestJsonClientProtocol;
import software.amazon.smithy.java.client.core.ClientConfig;
import software.amazon.smithy.java.client.core.ClientProtocol;
import software.amazon.smithy.java.client.core.endpoint.EndpointResolver;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.S3ECTestServerApiService;
import software.amazon.smithy.java.http.api.HttpRequest;
import software.amazon.smithy.java.http.api.HttpResponse;

public class TestUtils {

    // Version name constants
    // Each language can have up to 3 versions:
    // vN-Current: Currently released version. Does not support setting commitment policy.
    // vN-Transition: Proposed feature release version. Supports reading messages encrypted with key commitment.
    // vN+1: Proposed breaking release version. Supports reading/writing messages encrypted with key commitment.

    public static final String JAVA_V3_TRANSITION = "Java-V3-Transition";
    public static final String JAVA_V4 = "Java-V4";

    // No Python S3EC versions are released. Only test V3 as the "vN+1" version.
    public static final String PYTHON_V3 = "Python-V3";

    public static final String GO_V3_TRANSITION = "Go-V3-Transition";
    public static final String GO_V4 = "Go-V4";

    public static final String NET_V2_TRANSITION = "NET-V2-Transition";
    public static final String NET_V3_TRANSITION = "NET-V3-Transition";
    public static final String NET_V4 = "NET-V4";

    public static final String CPP_V2_TRANSITION = "CPP-V2-Transition";
    public static final String CPP_V3 = "CPP-V3";

    public static final String RUBY_V2_TRANSITION = "Ruby-V2-Transition";
    public static final String RUBY_V3 = "Ruby-V3";

    public static final String PHP_V2_TRANSITION = "PHP-V2-Transition";
    public static final String PHP_V3 = "PHP-V3";

    // Test configuration constants
    public static final String KMS_KEY_ARN = System.getenv("TEST_SERVER_KMS_KEY_ARN") != null ?
        System.getenv("TEST_SERVER_KMS_KEY_ARN") : "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Test-Server-Github-KMS-Key";
    public static final Region KMS_REGION = Region.getRegion(Regions.fromName("us-west-2"));
    public static final String BUCKET = System.getenv("TEST_SERVER_S3_BUCKET") != null ? 
        System.getenv("TEST_SERVER_S3_BUCKET") : "s3ec-test-server-github-bucket";

    // Sets of unsupported features by language
    public static final Set<String> ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED =
      Set.of(PHP_V2_TRANSITION, PHP_V3, NET_V3_TRANSITION, NET_V4);
    
    public static final Set<String> ENCRYPTION_CONTEXT_ON_ENCRYPT_UNSUPPORTED =
      Set.of(NET_V3_TRANSITION, NET_V4);

    public static final Set<String> RE_ENCRYPT_SUPPORTED =
      Set.of(JAVA_V3_TRANSITION, JAVA_V4);

    public static final Set<String> RANGED_GETS_SUPPORTED =
        Set.of(
          JAVA_V3_TRANSITION, JAVA_V4, CPP_V2_TRANSITION, CPP_V3
        );

    // Cpp only supports Raw AES
    public static final Set<String> RAW_AES_SUPPORTED =
      Set.of(JAVA_V3_TRANSITION, JAVA_V4, NET_V3_TRANSITION, NET_V4, RUBY_V2_TRANSITION, RUBY_V3, CPP_V2_TRANSITION, CPP_V3);

    public static final Set<String> RAW_RSA_SUPPORTED =
      Set.of(JAVA_V3_TRANSITION, JAVA_V4, NET_V3_TRANSITION, NET_V4, RUBY_V2_TRANSITION, RUBY_V3);

    // Intersection of RAW_AES_SUPPORTED and RAW_RSA_SUPPORTED
    public static final Set<String> RAW_SUPPORTED =
    RAW_AES_SUPPORTED.stream()
        .filter(RAW_RSA_SUPPORTED::contains)
        .collect(Collectors.toSet());

    // .NET only supports decrypting instruction files using AES and RSA.
    // Python MUST support decrypting KMS instruction files, but does not yet.
    public static final Set<String> KMS_INSTRUCTION_FILE_UNSUPPORTED =
      Set.of(NET_V2_TRANSITION, NET_V3_TRANSITION, NET_V4);

    // Go does not write with instruction files
    public static final Set<String> INSTRUCTION_FILE_PUT_UNSUPPORTED =
      Set.of(GO_V3_TRANSITION, GO_V4, PYTHON_V3);

    // Not implemented yet in Python.
    public static final Set<String> INSTRUCTION_FILE_GET_UNSUPPORTED =
      Set.of(PYTHON_V3);

    // Languages that support custom instruction file suffix on GetObject
    // Only Java, Ruby, and PHP servers have been updated with this feature
    // This is a current gap.
    public static final Set<String> CUSTOM_INSTRUCTION_SUFFIX_GET_SUPPORTED =
      Set.of(
        JAVA_V3_TRANSITION,
        JAVA_V4,
        RUBY_V2_TRANSITION,
        RUBY_V3,
        PHP_V2_TRANSITION,
        PHP_V3
      );

    public static final Set<String> TRANSITION_VERSIONS =
        Set.of(
            JAVA_V3_TRANSITION,
            GO_V3_TRANSITION,
            NET_V3_TRANSITION,
            CPP_V2_TRANSITION,
            PHP_V2_TRANSITION,
            RUBY_V2_TRANSITION
        );

    public static final Set<String> IMPROVED_VERSIONS =
        Set.of(
            JAVA_V4,
            PYTHON_V3,
            GO_V4,
            NET_V4,
            CPP_V3,
            PHP_V3,
            RUBY_V3
        );

    private static final Map<String, LanguageServerTarget> serverMap;

    static {
        final Map<String, LanguageServerTarget> servers = new LinkedHashMap<>();
        servers.put(PYTHON_V3, new LanguageServerTarget(PYTHON_V3, "8081"));
        servers.put(CPP_V2_TRANSITION, new LanguageServerTarget(CPP_V2_TRANSITION, "8097"));
        servers.put(CPP_V3, new LanguageServerTarget(CPP_V3, "8091"));
        servers.put(GO_V4, new LanguageServerTarget(GO_V4, "8089"));
        servers.put(NET_V4, new LanguageServerTarget(NET_V4, "8090"));
        servers.put(RUBY_V3, new LanguageServerTarget(RUBY_V3, "8092"));
        servers.put(PHP_V3, new LanguageServerTarget(PHP_V3, "8093"));
        servers.put(JAVA_V3_TRANSITION, new LanguageServerTarget(JAVA_V3_TRANSITION, "8094"));
        servers.put(GO_V3_TRANSITION, new LanguageServerTarget(GO_V3_TRANSITION, "8095"));
        servers.put(RUBY_V2_TRANSITION, new LanguageServerTarget(RUBY_V2_TRANSITION, "8098"));
        servers.put(PHP_V2_TRANSITION, new LanguageServerTarget(PHP_V2_TRANSITION, "8099"));
        servers.put(JAVA_V4, new LanguageServerTarget(JAVA_V4, "8088"));
        servers.put(NET_V3_TRANSITION, new LanguageServerTarget(NET_V3_TRANSITION, "8100"));
        serverMap = filterServers(servers);

        System.out.println("=== Configured Test Servers ===");
        System.out.println("\nServers:");
        serverMap.forEach((name, target) -> {
            System.out.println("  " + name + " -> " + target.getServerURI());
        });
        System.out.println("\nTotal servers configured: " + serverMap.size());
        System.out.println("================================");
    }

    public static class LanguageServerTarget {
        private final String baseURI = "http://localhost";
        private String languageName;
        private URI serverURI;

        public LanguageServerTarget(String language, String port) {
            languageName = language;
            serverURI = URI.create(baseURI + ":" + port);
        }

        public String getLanguageName() {
            return languageName;
        }

        public URI getServerURI() {
            return serverURI;
        }

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

        @Override
        public String toString() {
            return languageName;
        }
    }

    /**
     * Filters the available servers based on system property test.filter.servers
     * @param allServers Map of all available servers
     * @return Filtered map of servers to use for testing
     */
    private static Map<String, LanguageServerTarget> filterServers(Map<String, LanguageServerTarget> allServers) {
        final String maybeFilter = System.getProperty("test.filter.servers");
        if (maybeFilter == null || maybeFilter.trim().isEmpty()) {
            return allServers; // No filtering - use all servers
        }

        System.out.println("Filtering with: " + maybeFilter);

        final String[] filters = Arrays.stream(maybeFilter.split(","))
            .map(String::trim)
            .map(String::toLowerCase)
            .toArray(String[]::new);

        return allServers.entrySet().stream()
            .filter(entry -> {
                String key = entry.getKey().toLowerCase();
                System.out.println("Checking server name:" + key);
                return Arrays.stream(filters).anyMatch(key::contains);
            })
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                Map.Entry::getValue,
                (e1, e2) -> e1, // merge function (not really needed)
                LinkedHashMap::new // preserve order
            ));
    }

    /**
     * Gets the map of available server targets for testing
     * @return Map of language names to server targets
     */
    public static Map<String, LanguageServerTarget> getServerMap() {
        return serverMap;
    }

    /**
     * Checks if a server is listening on the specified URI
     * @param uri The URI to check
     * @return true if server is listening, false otherwise
     */
    public static boolean serverListening(URI uri) {
        try (Socket ignored = new Socket(uri.getHost(), uri.getPort())) {
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Creates a test server client for the specified language server target
     * @param server The language server target
     * @return Configured S3ECTestServerClient
     */
    public static S3ECTestServerClient testServerClientFor(LanguageServerTarget server) {
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

    /**
     * Converts a metadata map to a list format for Smithy serialization
     * Annoyingly, Smithy doesn't provide an interface for map types
     * in HTTP headers, so we have to do the serde ourselves
     * @param md The metadata map
     * @return List representation of the metadata
     */
    public static List<String> metadataMapToList(Map<String, String> md) {
        List<String> mdAsList = new ArrayList<>(md.size());
        for (Map.Entry<String, String> keyValue : md.entrySet()) {
            // Using ":" because Smithy will parse "," into a flattened list
            mdAsList.add("[" + keyValue.getKey() + "]:[" + keyValue.getValue() + "]");
        }
        return mdAsList;
    }

    /**
     * Validates that all servers in the server map are running
     * @throws RuntimeException if any server is not running
     */
    public static void validateServersRunning() {
        for (LanguageServerTarget server : serverMap.values()) {
            if (!serverListening(server.getServerURI())) {
                throw new RuntimeException(String.format("Test Server for %s is not running at endpoint: %s",
                    server.getLanguageName(), server.getServerURI()));
            }
        }
    }

    /**
     * Provides a stream of arguments for parameterized tests that test individual clients
     * @return Stream of Arguments containing language names for testing
     */
    public static Stream<Arguments> clientsForTest() {
        return serverMap.values().stream()
            .map(Arguments::of);
    }

    /**
     * Get stream of arguments for transition version clients for testing.
     */
    public static Stream<Arguments> transitionClientsForTest() {
        return serverMap.values().stream()
            .filter(target -> TRANSITION_VERSIONS.contains(target.getLanguageName()))
            .map(Arguments::of);
    }

    /**
     * Get stream of arguments for improved version clients for testing.
     */
    public static Stream<Arguments> improvedClientsForTest() {
        return serverMap.values().stream()
            .filter(target -> IMPROVED_VERSIONS.contains(target.getLanguageName()))
            .map(Arguments::of);
    }

    /**
     * Get stream of arguments for clients that support RAW AES (includes CPP).
     */
    public static Stream<Arguments> clientsRawAesForTest() {
        Stream<Arguments> improved = improvedClientsForTest()
            .filter(target -> RAW_AES_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        Stream<Arguments> transition = transitionClientsForTest()
            .filter(target -> RAW_AES_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        return Stream.concat(improved, transition);
    }

    /**
     * Get stream of arguments for clients that support RAW RSA (excludes CPP).
     */
    public static Stream<Arguments> clientsRawRsaForTest() {
        Stream<Arguments> improved = improvedClientsForTest()
            .filter(target -> RAW_RSA_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        Stream<Arguments> transition = transitionClientsForTest()
            .filter(target -> RAW_RSA_SUPPORTED.contains(((LanguageServerTarget) target.get()[0]).getLanguageName()));
        return Stream.concat(improved, transition);
    }

    /**
     * These functions provide a stream of arguments for parameterized tests.
     * @return Stream of Arguments containing pairs of LanguageServerTarget for encryption and decryption
     */
    public static Stream<Arguments> encryptImprovedDecryptImproved() {
        return improvedClientsForTest()
            .flatMap(encrypt -> improvedClientsForTest()
                .flatMap(decrypt -> Stream.of(
                    Arguments.of(encrypt.get()[0], decrypt.get()[0])
                )));
    }

    public static Stream<Arguments> encryptImprovedDecryptTransition() {
        return improvedClientsForTest()
            .flatMap(encrypt -> transitionClientsForTest()
                .flatMap(decrypt -> Stream.of(
                    Arguments.of(encrypt.get()[0], decrypt.get()[0])
                )));
    }

    public static Stream<Arguments> encryptTransitionDecryptImproved() {
        return transitionClientsForTest()
            .flatMap(encrypt -> improvedClientsForTest()
                .flatMap(decrypt -> Stream.of(
                    Arguments.of(encrypt.get()[0], decrypt.get()[0])
                )));
    }

    /**
     * Provides a stream of arguments for parameterized tests that test cross-language compatibility
     * @return Stream of Arguments containing pairs of LanguageServerTarget for encryption and decryption
     */
    public static Stream<Arguments> crossLanguageClients() {
        return serverMap.values().stream()
            .flatMap(t1 -> serverMap.values().stream()
                .flatMap(t2 -> Stream.of(
                    Arguments.of(t1, t2)
                )));
    }

    /**
     * For a given string, append a suffix to distinguish it from
     * simultaneous test runs.
     * @param s The string to append the suffix to
     * @return The string with the suffix appended
     */
    public static String appendTestSuffix(final String s) {
        StringBuilder stringBuilder = new StringBuilder(s);
        stringBuilder.append(DateTimeFormat.forPattern("-yyMMdd-hhmmss-").print(new DateTime()));
        stringBuilder.append((int) (Math.random() * 100000));
        return stringBuilder.toString();
    }

    private static AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();
    public static EncryptionAlgorithm GetEncryptionAlgorithm(String objectKey)
    {
        // Lambda to determine encryption algorithm from a metadata map
        java.util.function.Function<Map<String, ?>, Optional<EncryptionAlgorithm>> getAlgorithmFromMap = (map) -> {
            if (map.containsKey("x-amz-c")) {
                return Optional.of(EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
            } else if (map.containsKey("x-amz-cek-alg")) {
                String cek = (String) map.get("x-amz-cek-alg");
                if (cek.contains("CBC")) {
                    return Optional.of(EncryptionAlgorithm.ALG_AES_256_CBC_IV16_NO_KDF);
                } else if (cek.contains("GCM")) {
                    return Optional.of(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF);
                }
            }
            return Optional.empty();
        };

        ObjectMetadata metadata = s3Client.getObjectMetadata(TestUtils.BUCKET, objectKey);
        Map<String, String> userMetadata = metadata.getUserMetadata();

        // Try to get algorithm from object metadata
        Optional<EncryptionAlgorithm> algorithm = getAlgorithmFromMap.apply(userMetadata);
        if (algorithm.isPresent()) {
            return algorithm.get();
        }

        // Check instruction file
        try {
            String instructionFileKey = objectKey + ".instruction";
            com.amazonaws.services.s3.model.S3Object instructionFileObject = 
                s3Client.getObject(TestUtils.BUCKET, instructionFileKey);
            
            // Read instruction file content
            java.io.InputStream inputStream = instructionFileObject.getObjectContent();
            String instructionFileJson = new String(
                inputStream.readAllBytes(), 
                java.nio.charset.StandardCharsets.UTF_8
            );
            inputStream.close();
            
            // Parse JSON to get metadata
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            Map<String, Object> instructionFileMap = mapper.readValue(instructionFileJson, Map.class);
            
            // Try to get algorithm from instruction file
            algorithm = getAlgorithmFromMap.apply(instructionFileMap);
            if (algorithm.isPresent()) {
                return algorithm.get();
            }
        } catch (Exception e) {
            // Instruction file doesn't exist or couldn't be read
        }

        throw new RuntimeException("Could not determine encryption algorithm from object metadata or instruction file!");
    }

    public static void Encrypt(
        S3ECTestServerClient client,
        String S3ECId,
        String objectKey,
        List<String> crossLanguageObjects,
        EncryptionAlgorithm expectedEncryptionAlgorithm
    ) {
        PutObjectOutput foo = client.putObject(PutObjectInput.builder()
        .clientID(S3ECId)
        .key(objectKey)
        .bucket(TestUtils.BUCKET)
        .body(ByteBuffer.wrap(objectKey.getBytes(StandardCharsets.UTF_8)))
        .build());

        assertEquals(
            expectedEncryptionAlgorithm,
            GetEncryptionAlgorithm(objectKey),
            "When encrypting the EncryptionAlgorithm does not match the expected value: " + expectedEncryptionAlgorithm
        );

        crossLanguageObjects.add(objectKey);
    }

    public static void Decrypt(
        S3ECTestServerClient client,
        String S3ECId,
        List<String> crossLanguageObjects,
        EncryptionAlgorithm expectedEncryptionAlgorithm
    ) {
        // Call 5-parameter version with crossLanguageObjects as expectedPlaintexts
        Decrypt(client, S3ECId, crossLanguageObjects, expectedEncryptionAlgorithm, crossLanguageObjects);
    }

    public static void Decrypt(
        S3ECTestServerClient client,
        String S3ECId,
        List<String> crossLanguageObjects,
        EncryptionAlgorithm expectedEncryptionAlgorithm,
        List<String> expectedPlaintexts
    ) {
        Decrypt(client, S3ECId, crossLanguageObjects, expectedEncryptionAlgorithm, expectedPlaintexts, null);
    }

    public static void Decrypt(
        S3ECTestServerClient client,
        String S3ECId,
        List<String> crossLanguageObjects,
        EncryptionAlgorithm expectedEncryptionAlgorithm,
        List<String> expectedPlaintexts,
        String instructionFileSuffix
    ) {
        if (crossLanguageObjects.isEmpty()) {
            fail("There is nothing to decrypt");
        }

        List<String> failures = new ArrayList<>();
        for (int i = 0; i < crossLanguageObjects.size(); i++) {
            try {
                String objectKey = crossLanguageObjects.get(i);
                String expectedPlaintext = expectedPlaintexts.get(i);
                
                GetObjectInput.Builder builder = GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey);
                
                // Add custom instruction file suffix if provided
                if (instructionFileSuffix != null && !instructionFileSuffix.isEmpty()) {
                    builder.instructionFileSuffix(instructionFileSuffix);
                }
                
                GetObjectOutput output = client.getObject(builder.build());

                // Then: Pass
                assertEquals(expectedPlaintext, new String(output.getBody().array()));
                assertEquals(
                    expectedEncryptionAlgorithm,
                    GetEncryptionAlgorithm(objectKey),
                    "When decrypting the EncryptionAlgorithm does not match the expected value: " + expectedEncryptionAlgorithm
                );
            } catch (Exception e) {
                failures.add(String.format(
                    "Failed to decrypt object '%s' (index %d): %s - %s",
                    crossLanguageObjects.get(i), i, e.getClass().getSimpleName(), e.getMessage()
                ));
            }
        }

        if (!failures.isEmpty()) {
            throw new AssertionError(String.format(
                "Decryption failed for %d out of %d objects:\n%s",
                failures.size(), crossLanguageObjects.size(), 
                String.join("\n", failures)
            ));
        }
    }

    /**
     * Decrypt helper for C++ clients that require materials description per-operation.
     * 
     * C++ SDK Design: Unlike Java/. NET/etc where materials description is embedded in the
     * keyring during client creation, the C++ SDK requires passing materials description
     * as a contextMap parameter to each GetObject/PutObject operation.
     * 
     * This helper extracts materials description from KeyMaterial and passes it via the
     * Content-Metadata header on each GetObject call, which the C++ server converts to
     * the contextMap parameter required by the C++ SDK.
     */
    public static void DecryptWithMaterialsDescription(
        S3ECTestServerClient client,
        String S3ECId,
        List<String> crossLanguageObjects,
        KeyMaterial keyMaterial,
        EncryptionAlgorithm expectedEncryptionAlgorithm
    ) {
        DecryptWithMaterialsDescription(client, S3ECId, crossLanguageObjects, keyMaterial,
            expectedEncryptionAlgorithm, crossLanguageObjects);
    }

    /**
     * Decrypt helper for C++ clients with custom expected plaintexts.
     */
    public static void DecryptWithMaterialsDescription(
        S3ECTestServerClient client,
        String S3ECId,
        List<String> crossLanguageObjects,
        KeyMaterial keyMaterial,
        EncryptionAlgorithm expectedEncryptionAlgorithm,
        List<String> expectedPlaintexts
    ) {
        if (crossLanguageObjects.isEmpty()) {
            throw new AssertionError("There is nothing to decrypt");
        }

        // Extract materials description from KeyMaterial
        List<String> metadata = (keyMaterial.getMaterialsDescription() != null)
            ? metadataMapToList(keyMaterial.getMaterialsDescription())
            : new ArrayList<>();

        List<String> failures = new ArrayList<>();
        for (int i = 0; i < crossLanguageObjects.size(); i++) {
            try {
                String objectKey = crossLanguageObjects.get(i);
                String expectedPlaintext = expectedPlaintexts.get(i);
                
                GetObjectOutput output = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .metadata(metadata)  // Pass materials description for C++
                    .build());

                // Then: Pass
                assertEquals(expectedPlaintext, new String(output.getBody().array()));
                assertEquals(
                    expectedEncryptionAlgorithm,
                    GetEncryptionAlgorithm(objectKey),
                    "When decrypting the EncryptionAlgorithm does not match the expected value: " + expectedEncryptionAlgorithm
                );
            } catch (Exception e) {
                failures.add(String.format(
                    "Failed to decrypt object '%s' (index %d): %s - %s",
                    crossLanguageObjects.get(i), i, e.getClass().getSimpleName(), e.getMessage()
                ));
            }
        }

        if (!failures.isEmpty()) {
            throw new AssertionError(String.format(
                "Decryption failed for %d out of %d objects:\n%s",
                failures.size(), crossLanguageObjects.size(), 
                String.join("\n", failures)
            ));
        }
    }

    /**
     * Attempts to encrypt an object and expects the operation to fail with an S3EncryptionClientError.
     * This is used for negative tests where the client configuration should prevent encryption
     * (e.g., commitment policy violations).
     *
     * The failure may occur during client creation (CreateClient) or during the PutObject call,
     * depending on when the server-side S3EC validates the configuration.
     */
    public static void Encrypt_fails(
        S3ECTestServerClient client,
        S3ECConfig config,
        String objectKey
    ) {
        try {
            CreateClientOutput clientOutput = client.createClient(CreateClientInput.builder()
                .config(config)
                .build());
            String S3ECId = clientOutput.getClientId();

            client.putObject(PutObjectInput.builder()
                .clientID(S3ECId)
                .key(objectKey)
                .bucket(TestUtils.BUCKET)
                .body(ByteBuffer.wrap(objectKey.getBytes(StandardCharsets.UTF_8)))
                .build());

            fail("Encryption should have failed for object: " + objectKey
                + " with config commitmentPolicy=" + config.getCommitmentPolicy()
                + " encryptionAlgorithm=" + config.getEncryptionAlgorithm());
        } catch (S3EncryptionClientError e) {
            // Expected - the S3EC should reject this configuration
        }
    }

    public static void Decrypt_fails(
        S3ECTestServerClient client,
        String S3ECId, List<String> crossLanguageObjects,
        EncryptionAlgorithm expectedEncryptionAlgorithm
    ) {

        if (crossLanguageObjects.isEmpty()) {
            throw new AssertionError("There is nothing to decrypt");
        }

        List<String> successfulDecrypt = new ArrayList<>();
        for (String objectKey : crossLanguageObjects) {
            try {

                assertEquals(
                  expectedEncryptionAlgorithm,
                    GetEncryptionAlgorithm(objectKey),
                    "Before decrypting the EncryptionAlgorithm does not match the expected value: " + expectedEncryptionAlgorithm
                );
                GetObjectOutput output = client.getObject(GetObjectInput.builder()
                .clientID(S3ECId)
                .bucket(TestUtils.BUCKET)
                .key(objectKey)
                .build());
                // It should fail to decrypt
                successfulDecrypt.add(objectKey);
            } catch (S3EncryptionClientError e) {
                // This is a success
                // TODO, add the failure message
            }
        }

        assertEquals(successfulDecrypt.size(), 0, "Decryption should have failed:" + String.join(",", successfulDecrypt));
    }

    /**
     * Perform ranged get operation with specified byte range
     */
    public static void RangedGet(
        S3ECTestServerClient client,
        String S3ECId,
        List<String> objectKeys,
        long rangeStart,
        long rangeEnd,
        EncryptionAlgorithm expectedEncryptionAlgorithm
    ) {

        if (objectKeys.isEmpty()) {
            throw new AssertionError("There is nothing to get");
        }

        List<String> failures = new ArrayList<>();
        for (String objectKey : objectKeys) {
            try {
                // Get the full object first to know expected content
                GetObjectOutput fullOutput = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .build());
                byte[] fullContent = fullOutput.getBody().array();
                
                // Perform ranged get
                GetObjectOutput output = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .range("bytes=" + rangeStart + "-" + rangeEnd)
                    .build());

                // Verify the ranged content matches expected slice
                byte[] rangedContent = output.getBody().array();
                int startIndex = (int) rangeStart;
                int endIndex = (int) Math.min(rangeEnd + 1, fullContent.length); // +1 because HTTP ranges are inclusive
                byte[] expectedContent = Arrays.copyOfRange(fullContent, startIndex, endIndex);
                assertArrayEquals(expectedContent, rangedContent, 
                    "Ranged get returned unexpected data for:" + objectKey);
                
                // Verify encryption algorithm
                assertEquals(
                    expectedEncryptionAlgorithm,
                    GetEncryptionAlgorithm(objectKey),
                    "Encryption algorithm mismatch for " + objectKey
                );
            } catch (Exception e) {
                failures.add(String.format(
                    "Failed ranged get on '%s': %s - %s",
                    objectKey, e.getClass().getSimpleName(), e.getMessage()
                ));
            }
        }

        if (!failures.isEmpty()) {
            throw new AssertionError(String.format(
                "Ranged get failed for %d out of %d objects:\n%s",
                failures.size(), objectKeys.size(), 
                String.join("\n", failures)
            ));
        }
    }

    /**
     * Perform ranged get operations that are expected to fail
     */
    public static void RangedGet_fails(
        S3ECTestServerClient client,
        String S3ECId,
        List<String> objectKeys,
        long rangeStart,
        long rangeEnd,
        EncryptionAlgorithm expectedEncryptionAlgorithm
    ) {

        if (objectKeys.isEmpty()) {
            throw new AssertionError("There is nothing to get");
        }

        List<String> successfulGets = new ArrayList<>();
        for (String objectKey : objectKeys) {
            try {
                assertEquals(
                    expectedEncryptionAlgorithm,
                    GetEncryptionAlgorithm(objectKey),
                    "Encryption algorithm mismatch for " + objectKey
                );
                
                GetObjectOutput output = client.getObject(GetObjectInput.builder()
                    .clientID(S3ECId)
                    .bucket(TestUtils.BUCKET)
                    .key(objectKey)
                    .range("bytes=" + rangeStart + "-" + rangeEnd)
                    .build());
                
                // Should have failed but didn't
                successfulGets.add(objectKey);
            } catch (S3EncryptionClientError e) {
                // This is expected - the ranged get should fail
            }
        }

        assertEquals(0, successfulGets.size(), 
            "Ranged get should have failed for: " + String.join(", ", successfulGets));
    }
}
