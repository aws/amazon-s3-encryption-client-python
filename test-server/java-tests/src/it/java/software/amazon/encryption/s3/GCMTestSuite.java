/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.encryption.s3;

import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.TestClassOrder;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

/**
 * GCM Test Suite
 * 
 * This suite enforces execution order between GCM encrypt and decrypt phases:
 * 1. GCMEncryptTests (@Order(1)) - All encrypt tests run in parallel (within this phase)
 * 2. GCMDecryptTests (@Order(2)) - All decrypt tests run in parallel (after encrypt phase completes)
 * 
 * This ensures that encrypted objects exist before decryption tests run,
 * while still allowing maximum parallelization within each phase.
 */
@Suite
@SelectClasses({GCMEncryptTests.class, GCMDecryptTests.class})
@TestClassOrder(ClassOrderer.OrderAnnotation.class)
public class GCMTestSuite {
    // Suite configuration only - no test methods needed
    // Test classes are ordered using @Order annotations on the classes themselves
}
