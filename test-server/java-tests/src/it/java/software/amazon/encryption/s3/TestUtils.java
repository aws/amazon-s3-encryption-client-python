/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.params.provider.Arguments;
import software.amazon.encryption.s3.client.S3ECTestServerClient;
import software.amazon.encryption.s3.model.*;
import software.amazon.smithy.java.aws.client.restjson.RestJsonClientProtocol;
import software.amazon.smithy.java.client.core.ClientConfig;
import software.amazon.smithy.java.client.core.ClientProtocol;
import software.amazon.smithy.java.client.core.endpoint.EndpointResolver;
import software.amazon.smithy.java.http.api.HttpRequest;
import software.amazon.smithy.java.http.api.HttpResponse;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;

/**
 * Shared utilities and constants for S3 Encryption Client tests.
 * This class contains common configuration, server setup, and helper methods
 * used across multiple test classes.
 */
public final class TestUtils {
    
    // Test configuration constants
    public static final String KMS_KEY_ARN = System.getenv("TEST_SERVER_KMS_KEY_ARN") != null ?
        System.getenv("TEST_SERVER_KMS_KEY_ARN") : "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Test-Server-Github-KMS-Key";
    public static final Region KMS_REGION = Region.getRegion(Regions.fromName("us-west-2"));
    public static final String BUCKET = System.getenv("TEST_SERVER_S3_BUCKET") != null ? 
        System.getenv("TEST_SERVER_S3_BUCKET") : "s3ec-test-server-github-bucket";

    // Version name constants
    // Each language can have up to 3 versions:
    // vN-Current: Currently released version. Does not support setting commitment policy.
    // vN-Transition: Proposed patch/feature release version with a new client class.
    //      Supports setting commitment policy; no default policy; MUST be explicitly configured on constructor.
    // vN+1: Proposed breaking release version.
    //      Supports setting commitment policy; defaults to `RequireEncryptRequireDecrypt`.

    public static final String JAVA_V3_CURRENT = "Java-V3-Current";
    public static final String JAVA_V3_TRANSITION = "Java-V3-Transition";
    public static final String JAVA_V4 = "Java-V4";

    // No Python S3EC versions are released. Only test V3 as the "vN+1" version.
    public static final String PYTHON_V3 = "Python-V3";

    public static final String GO_V3_CURRENT = "Go-V3-Current";
    public static final String GO_V3_TRANSITION = "Go-V3-Transition";
    public static final String GO_V4 = "Go-V4";

    public static final String NET_V2_CURRENT = "Net-V2-Current";
    public static final String NET_V2_TRANSITION = "Net-V2-Transition";
    public static final String NET_V3 = "Net-V3";

    public static final String CPP_V2_CURRENT = "Cpp-V2-Current";
    public static final String CPP_V2_TRANSITION = "Cpp-V2-Transition";
    public static final String CPP_V3 = "Cpp-V3";

    public static final String RUBY_V2_CURRENT = "Ruby-V2-Current";
    public static final String RUBY_V2_TRANSITION = "Ruby-V2-Transition";
    public static final String RUBY_V3 = "Ruby-V3";

    public static final String PHP_V2_CURRENT = "PHP-V2-Current";
    public static final String PHP_V2_TRANSITION = "PHP-V2-Transition";
    public static final String PHP_V3 = "PHP-V3";

    // Server configuration
    private static final List<LanguageServerTarget> serverList;
    private static final Map<String, LanguageServerTarget> serverMap;

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
    public static final Set<String> ENCRYPTION_CONTEXT_ON_DECRYPT_UNSUPPORTED =
        Set.of("Go-V3");

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
            JAVA_V3_TRANSITION,
            GO_V3_TRANSITION,
            NET_V2_TRANSITION,
            CPP_V2_TRANSITION,
            RUBY_V2_TRANSITION,
            PHP_V2_TRANSITION
        );

    public static final Set<String> IMPROVED_VERSIONS =
        Set.of(
            JAVA_V4,
            PYTHON_V3,
            GO_V4,
            NET_V3,
            CPP_V3,
            RUBY_V3,
            PHP_V3
        );

    /**
     * Language server target class for test server configuration.
     */
    public static class LanguageServerTarget {
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

        public LanguageServerTarget(String language, String port) {
            languageName = language;
            serverURI = URI.create(baseURI+ ":" + port);
        }

        @Override
        public String toString() {
            return languageName;
        }
    }

    // Private constructor to prevent instantiation
    private TestUtils() {
        throw new UnsupportedOperationException("Utility class should not be instantiated");
    }

    /**
     * Get the list of configured test servers.
     */
    public static List<LanguageServerTarget> getServerList() {
        return new ArrayList<>(serverList);
    }

    /**
     * Get the map of server names to server targets.
     */
    public static Map<String, LanguageServerTarget> getServerMap() {
        return new HashMap<>(serverMap);
    }

    /**
     * Check if a server is listening on the specified URI.
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
     * Create a test server client for the specified server target.
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
     * Get stream of arguments for all clients for testing.
     */
    public static Stream<Arguments> clientsForTest() {
        return serverList.stream()
          .map(LanguageServerTarget::getLanguageName)
          .map(Arguments::of);
    }

    /**
     * Get stream of arguments for current version clients for testing.
     */
    public static Stream<Arguments> currentClientsForTest() {
        return clientsForTest()
          .filter(arg -> CURRENT_VERSIONS.contains(arg.get()[0]));
    }

    /**
     * Get stream of arguments for transition version clients for testing.
     */
    public static Stream<Arguments> transitionClientsForTest() {
        return clientsForTest()
          .filter(arg -> TRANSITION_VERSIONS.contains(arg.get()[0]));
    }

    /**
     * Get stream of arguments for improved version clients for testing.
     */
    public static Stream<Arguments> improvedClientsForTest() {
        return clientsForTest()
          .filter(arg -> IMPROVED_VERSIONS.contains(arg.get()[0]));
    }

    /**
     * Get stream of arguments for cross-language client combinations.
     */
    public static Stream<Arguments> crossLanguageClients() {
        return serverList.stream()
          .flatMap(t1 -> serverList.stream()
            .flatMap(t2 -> Stream.of(
              Arguments.of(t1, t2)
            )));
    }

    /**
     * Get stream of arguments for cross-language client combinations with algorithm suite.
     */
    public static Stream<Arguments> crossLanguageClientsWithAlgSuite() {
        return serverList.stream()
          .flatMap(t1 -> serverList.stream()
            .flatMap(t2 -> Stream.of(
              Arguments.of(t1, t2)
            )));
    }

    /**
     * Convert a metadata map to a list format for Smithy serialization.
     * Annoyingly, Smithy doesn't provide an interface for map types
     * in HTTP headers, so we have to do the serde ourselves.
     * Servers need an equivalent utility.
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
     * Setup method to verify all test servers are running.
     * Should be called from @BeforeAll methods in test classes.
     */
    public static void setupTestServers() {
        // Wait for servers to start
        for (LanguageServerTarget server : serverList) {
            if (!serverListening(server.getServerURI())) {
                throw new RuntimeException(String.format("Test Server for %s is not running at endpoint: %s", server.getLanguageName(), server.getServerURI()));
            }
        }
    }
}
