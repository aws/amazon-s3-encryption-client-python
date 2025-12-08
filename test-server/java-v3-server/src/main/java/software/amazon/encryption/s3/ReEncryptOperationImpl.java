package software.amazon.encryption.s3;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.encryption.s3.internal.ReEncryptInstructionFileRequest;
import software.amazon.encryption.s3.internal.ReEncryptInstructionFileResponse;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.MaterialsDescription;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RawKeyring;
import software.amazon.encryption.s3.materials.RsaKeyring;
import software.amazon.encryption.s3.model.GenericServerError;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.model.ReEncryptInput;
import software.amazon.encryption.s3.model.ReEncryptOutput;
import software.amazon.encryption.s3.model.S3EncryptionClientError;
import software.amazon.encryption.s3.service.ReEncryptOperation;
import software.amazon.smithy.java.server.RequestContext;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
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

            // Create a new keyring from the provided newKeyMaterial
            KeyMaterial newKeyMaterial = input.getNewKeyMaterial();
            if (newKeyMaterial == null) {
                throw new IllegalStateException(
                    "newKeyMaterial is required for ReEncrypt operation");
            }
            
            RawKeyring newKeyring = createKeyringFromMaterial(newKeyMaterial);

            try {
                // Build the ReEncryptInstructionFileRequest
                ReEncryptInstructionFileRequest.Builder requestBuilder = 
                    ReEncryptInstructionFileRequest.builder()
                        .bucket(input.getBucket())
                        .key(input.getKey())
                        .newKeyring(newKeyring);
                
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

    /**
     * Creates a RawKeyring from KeyMaterial.
     * The KeyMaterial should have exactly one of: aesKey, rsaKey, or kmsKeyId set.
     */
    private RawKeyring createKeyringFromMaterial(KeyMaterial keyMaterial) {
        try {
            // Get materials description from KeyMaterial if provided
            MaterialsDescription materialsDescription = null;
            if (keyMaterial.getMaterialsDescription() != null && !keyMaterial.getMaterialsDescription().isEmpty()) {
                MaterialsDescription.Builder builder = MaterialsDescription.builder();
                for (Map.Entry<String, String> entry : keyMaterial.getMaterialsDescription().entrySet()) {
                    builder.put(entry.getKey(), entry.getValue());
                }
                materialsDescription = builder.build();
            }
            
            // Check for AES key
            if (keyMaterial.getAesKey() != null) {
                byte[] aesKeyBytes = new byte[keyMaterial.getAesKey().remaining()];
                keyMaterial.getAesKey().get(aesKeyBytes);
                SecretKey secretKey = new SecretKeySpec(aesKeyBytes, "AES");
                
                AesKeyring.Builder keyringBuilder = AesKeyring.builder()
                        .wrappingKey(secretKey);
                
                if (materialsDescription != null) {
                    keyringBuilder.materialsDescription(materialsDescription);
                }
                
                return keyringBuilder.build();
            }
            
            // Check for RSA key
            if (keyMaterial.getRsaKey() != null) {
                byte[] rsaKeyBytes = new byte[keyMaterial.getRsaKey().remaining()];
                keyMaterial.getRsaKey().get(rsaKeyBytes);
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(rsaKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
                
                // Derive the public key from the private key
                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                        privateKey.getModulus(),
                        privateKey.getPublicExponent()
                );
                PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
                
                PartialRsaKeyPair keyPair = PartialRsaKeyPair.builder()
                        .privateKey(privateKey)
                        .publicKey(publicKey)
                        .build();
                
                RsaKeyring.Builder keyringBuilder = RsaKeyring.builder()
                        .wrappingKeyPair(keyPair);
                
                if (materialsDescription != null) {
                    keyringBuilder.materialsDescription(materialsDescription);
                }
                
                return keyringBuilder.build();
            }
            
            throw new IllegalStateException(
                "KeyMaterial must have either aesKey or rsaKey set");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create keyring from KeyMaterial: " + e.getMessage(), e);
        }
    }
}
