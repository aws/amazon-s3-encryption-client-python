package software.amazon.encryption.s3;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.encryption.s3.internal.ReEncryptInstructionFileRequest;
import software.amazon.encryption.s3.internal.ReEncryptInstructionFileResponse;
import software.amazon.encryption.s3.materials.RawKeyring;
import software.amazon.encryption.s3.model.GenericServerError;
import software.amazon.encryption.s3.model.ReEncryptInput;
import software.amazon.encryption.s3.model.ReEncryptOutput;
import software.amazon.encryption.s3.model.S3EncryptionClientError;
import software.amazon.encryption.s3.service.ReEncryptOperation;
import software.amazon.smithy.java.server.RequestContext;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;

public class ReEncryptOperationImpl implements ReEncryptOperation {
    private final Map<String, S3Client> clientCache_;
    private final Map<String, software.amazon.encryption.s3.materials.Keyring> keyringCache_;

    public ReEncryptOperationImpl(Map<String, S3Client> clientCache, Map<String, software.amazon.encryption.s3.materials.Keyring> keyringCache) {
        clientCache_ = clientCache;
        keyringCache_ = keyringCache;
    }

    @Override
    public ReEncryptOutput reEncrypt(ReEncryptInput input, RequestContext context) {
        try {
            S3Client s3Client = clientCache_.get(input.getClientID());
            
            // Ensure we have an S3EncryptionClient, not just a plain S3Client
            if (!(s3Client instanceof S3EncryptionClient)) {
                throw new IllegalStateException(
                    "Client " + input.getClientID() + " is not an S3EncryptionClient");
            }
            
            S3EncryptionClient s3EncryptionClient = (S3EncryptionClient) s3Client;

            // Get the keyring from cache and cast to RawKeyring
            software.amazon.encryption.s3.materials.Keyring cachedKeyring = keyringCache_.get(input.getClientID());
            if (cachedKeyring == null) {
                throw new IllegalStateException(
                    "No keyring found for client " + input.getClientID());
            }
            
            if (!(cachedKeyring instanceof RawKeyring)) {
                throw new IllegalStateException(
                    "Keyring for client " + input.getClientID() + " is not a RawKeyring");
            }
            
            RawKeyring keyring = (RawKeyring) cachedKeyring;

            try {
                // Build the ReEncryptInstructionFileRequest
                ReEncryptInstructionFileRequest.Builder requestBuilder = 
                    ReEncryptInstructionFileRequest.builder()
                        .bucket(input.getBucket())
                        .key(input.getKey())
                        .newKeyring(keyring);
                
                // Add optional instruction file suffix if provided
                if (input.getInstructionFileSuffix() != null && !input.getInstructionFileSuffix().isEmpty()) {
                    requestBuilder.instructionFileSuffix(input.getInstructionFileSuffix());
                }
                
                // Add optional enforceRotation if provided
                if (input.isEnforceRotation() != null) {
                    requestBuilder.enforceRotation(input.isEnforceRotation());
                }
                
                ReEncryptInstructionFileRequest reEncryptRequest = requestBuilder.build();
                
                // Perform the re-encryption
                ReEncryptInstructionFileResponse response = 
                    s3EncryptionClient.reEncryptInstructionFile(reEncryptRequest);
                
                // Build and return the output
                return ReEncryptOutput.builder()
                        .bucket(response.bucket())
                        .key(response.key())
                        .instructionFileSuffix(response.instructionFileSuffix())
                        .enforceRotation(response.enforceRotation())
                        .build();
                        
            } catch (S3EncryptionClientException s3EncryptionClientException) {
                // Modeled exceptions MUST be returned as such
                StringWriter sw = new StringWriter();
                s3EncryptionClientException.printStackTrace(new PrintWriter(sw));
                String stackTrace = sw.toString();
                throw S3EncryptionClientError.builder()
                        .message(stackTrace)
                        .build();
            }
        } catch (Exception e) {
            // Don't wrap modeled errors
            if (e instanceof S3EncryptionClientError) {
                throw e;
            }
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String stackTrace = sw.toString();
            throw GenericServerError.builder()
                    .message(stackTrace)
                    .build();
        }
    }
}
