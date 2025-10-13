/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.junit.jupiter.params.provider.Arguments;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
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

    public static final String JAVA_V3_CURRENT = "Java-V3-Current";
    public static final String JAVA_V3_TRANSITION = "Java-V3-Transition";
    public static final String JAVA_V4 = "Java-V4";

    // No Python S3EC versions are released. Only test V3 as the "vN+1" version.
    public static final String PYTHON_V3 = "Python-V3";

    public static final String GO_V3_CURRENT = "Go-V3-Current";
    public static final String GO_V3_TRANSITION = "Go-V3-Transition";
    public static final String GO_V4 = "Go-V4";

    public static final String NET_V2_CURRENT = "NET-V2-Current";
    public static final String NET_V2_TRANSITION = "NET-V2-Transition";
    public static final String NET_V3 = "NET-V3";

    public static final String CPP_V2_CURRENT = "CPP-V2-Current";
    public static final String CPP_V2_TRANSITION = "CPP-V2-Transition";
    public static final String CPP_V3 = "CPP-V3";

    public static final String RUBY_V2_CURRENT = "Ruby-V2-Current";
    public static final String RUBY_V2_TRANSITION = "Ruby-V2-Transition";
    public static final String RUBY_V3 = "Ruby-V3";

    public static final String PHP_V2_CURRENT = "PHP-V2-Current";
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
        Set.of(GO_V3_CURRENT, PHP_V2_CURRENT, PHP_V2_TRANSITION, PHP_V3, NET_V2_CURRENT, NET_V3);
    
    public static final Set<String> ENCRYPTION_CONTEXT_ON_ENCRYPT_UNSUPPORTED =
        Set.of(NET_V2_CURRENT, NET_V3);

    public static final Set<String> CURRENT_VERSIONS =
        Set.of(
            JAVA_V3_CURRENT,
            GO_V3_CURRENT,
            NET_V2_CURRENT,
            CPP_V2_CURRENT,
            RUBY_V2_CURRENT,
            PHP_V2_CURRENT
        );

    public static final Set<String> TRANSITION_VERSIONS =
        Set.of(
            // JAVA_V3_TRANSITION,
            // GO_V3_TRANSITION,
            // NET_V2_TRANSITION,
            // CPP_V2_TRANSITION,
            // PHP_V2_TRANSITION,
            RUBY_V2_TRANSITION
        );

    public static final Set<String> IMPROVED_VERSIONS =
        Set.of(
            // JAVA_V4,
            // PYTHON_V3,
            // GO_V4,
            // NET_V3,
            // CPP_V3,
            // PHP_V3,
            RUBY_V3
        );

    private static final Map<String, LanguageServerTarget> serverMap;

    static {
        final Map<String, LanguageServerTarget> servers = new LinkedHashMap<>();
        servers.put(JAVA_V3_CURRENT, new LanguageServerTarget(JAVA_V3_CURRENT, "8080"));
        servers.put(PYTHON_V3, new LanguageServerTarget(PYTHON_V3, "8081"));
        servers.put(GO_V3_CURRENT, new LanguageServerTarget(GO_V3_CURRENT, "8082"));
        servers.put(NET_V2_CURRENT, new LanguageServerTarget(NET_V2_CURRENT, "8083"));
        servers.put(NET_V3, new LanguageServerTarget(NET_V3, "8084"));
        servers.put(CPP_V2_CURRENT, new LanguageServerTarget(CPP_V2_CURRENT, "8085"));
        servers.put(RUBY_V2_CURRENT, new LanguageServerTarget(RUBY_V2_CURRENT, "8086"));
        servers.put(PHP_V2_CURRENT, new LanguageServerTarget(PHP_V2_CURRENT, "8087"));
        servers.put(GO_V4, new LanguageServerTarget(GO_V4, "8089"));
        servers.put(RUBY_V3, new LanguageServerTarget(RUBY_V3, "8092"));
        servers.put(PHP_V3, new LanguageServerTarget(PHP_V3, "8093"));
        // TODO: Create and add transition servers
        servers.put(JAVA_V3_TRANSITION, new LanguageServerTarget(JAVA_V3_TRANSITION, "8094"));
        // servers.put(GO_V3_TRANSITION, new LanguageServerTarget(GO_V3_TRANSITION, "8095"));
        // servers.put(NET_V2_TRANSITION, new LanguageServerTarget(NET_V2_TRANSITION, "8096"));
        servers.put(CPP_V2_TRANSITION, new LanguageServerTarget(CPP_V2_TRANSITION, "8097"));
        // servers.put(RUBY_V2_TRANSITION, new LanguageServerTarget(RUBY_V2_TRANSITION, "8098"));
        servers.put(PHP_V2_TRANSITION, new LanguageServerTarget(PHP_V2_TRANSITION, "8099"));
        servers.put(JAVA_V4, new LanguageServerTarget(JAVA_V4, "8090"));
        serverMap = filterServers(servers);
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

        final String[] filters = Arrays.stream(maybeFilter.split(","))
            .map(String::trim)
            .map(String::toLowerCase)
            .toArray(String[]::new);

        return allServers.entrySet().stream()
            .filter(entry -> {
                String key = entry.getKey().toLowerCase();
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
     * Get stream of arguments for current version clients for testing.
     */
    public static Stream<Arguments> currentClientsForTest() {
        return serverMap.values().stream()
            .filter(target -> CURRENT_VERSIONS.contains(target.getLanguageName()))
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

    public static Stream<Arguments> encryptImprovedDecryptCurrent() {
        return improvedClientsForTest()
            .flatMap(encrypt -> currentClientsForTest()
                .flatMap(decrypt -> Stream.of(
                    Arguments.of(encrypt.get()[0], decrypt.get()[0])
                )));
    }

    public static Stream<Arguments> encryptCurrentDecryptImproved() {
        return currentClientsForTest()
            .flatMap(encrypt -> improvedClientsForTest()
                .flatMap(decrypt -> Stream.of(
                    Arguments.of(encrypt.get()[0], decrypt.get()[0])
                )));
    }

    public static Stream<Arguments> encryptTransitionDecryptCurrent() {
        return transitionClientsForTest()
            .flatMap(encrypt -> currentClientsForTest()
                .flatMap(decrypt -> Stream.of(
                    Arguments.of(encrypt.get()[0], decrypt.get()[0])
                )));
    }

    public static Stream<Arguments> encryptCurrentDecryptTransition() {
        return currentClientsForTest()
            .flatMap(encrypt -> transitionClientsForTest()
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
}
