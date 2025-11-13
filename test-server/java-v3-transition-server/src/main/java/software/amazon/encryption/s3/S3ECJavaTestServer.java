/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import software.amazon.awssdk.services.s3.S3Client;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

import software.amazon.smithy.java.server.Server;
import software.amazon.encryption.s3.service.S3ECTestServer;

public class S3ECJavaTestServer implements Runnable {
    static final URI endpoint = URI.create("http://localhost:8094");

    public static void main(String[] args) {
        new S3ECJavaTestServer().run();
    }

    @Override
    public void run() {
        // All the S3EC instances live here.
        // Obviously this can get messy in a real service.
        // Assume that the tests behave and don't induce weird race conditions.
        Map<String, S3Client> clientCache = new ConcurrentHashMap<>();

        Server server = Server.builder()
                .endpoints(endpoint)
                .addService(
                        S3ECTestServer.builder()
                                .addCreateClientOperation(new CreateClientOperationImpl(clientCache))
                                .addGetObjectOperation(new GetObjectOperationImpl(clientCache))
                                .addPutObjectOperation(new PutObjectOperationImpl(clientCache))
                                .build())
                .build();
        System.out.println("Starting server...");
        server.start();
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            System.out.println("Stopping server...");
            try {
                server.shutdown().get();
            } catch (InterruptedException | ExecutionException ex) {
                throw new RuntimeException(ex);
            }
        }
    }
}
