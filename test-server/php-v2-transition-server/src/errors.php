<?php

/**
 * Used for "internal" errors, e.g. problems with the test server itself
 * Tests MUST NOT expect this error in negative tests.
 * 
 * @param string $message The error message to include in the response
 * @param int $code The error code to set in the response
 * @return string JSON-encoded error response
 */
function GenericServerError($message, $code = 500)
{
    http_response_code(500);
    header('Content-Type: application/json');

    $errorResponse = [
        'error' => 'GenericServerError',
        'message' => $message
    ];

    return json_encode($errorResponse);
}

/**
 * Used for modeled errors, e.g. errors thrown by the S3EC
 * Tests SHOULD expect this error in negative tests.
 * 
 * @param string $message The error message to include in the response
 * @return string JSON-encoded error response
 */
function S3EncryptionClientError($message)
{
    http_response_code(500);
    header('Content-Type: application/json');

    $errorResponse = [
        "__type" => "software.amazon.encryption.s3#S3EncryptionClientError",
        'message' => $message
    ];

    return json_encode($errorResponse);
}
