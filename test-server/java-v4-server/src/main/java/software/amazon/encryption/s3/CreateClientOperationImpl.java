package software.amazon.encryption.s3;

import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.core.retry.backoff.BackoffStrategy;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.Keyring;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.materials.MaterialsDescription;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RsaKeyring;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.EncryptionAlgorithm;
import software.amazon.encryption.s3.model.GenericServerError;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.service.CreateClientOperation;
import software.amazon.smithy.java.server.RequestContext;

import javax.crypto.spec.SecretKeySpec;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Map;
import java.util.UUID;

import static software.amazon.encryption.s3.CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT;
import static software.amazon.encryption.s3.CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT;
import static software.amazon.encryption.s3.CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

public class CreateClientOperationImpl implements CreateClientOperation {
    private final Map<String, S3Client> clientCache_;
    private final Map<String, Keyring> keyringCache_;

    public CreateClientOperationImpl(Map<String, S3Client> clientCache, Map<String, Keyring> keyringCache) {
        clientCache_ = clientCache;
        keyringCache_ = keyringCache;
    }

    // Copied from S3EC.
    private boolean onlyOneNonNull(Object... values) {
        boolean haveOneNonNull = false;
        for (Object o : values) {
            if (o != null) {
                if (haveOneNonNull) {
                    return false;
                }

                haveOneNonNull = true;
            }
        }

        return haveOneNonNull;
    }

    @Override
    public CreateClientOutput createClient(CreateClientInput input, RequestContext context) {
        try {
            KeyMaterial key = input.getConfig().getKeyMaterial();
            if (!onlyOneNonNull(key.getAesKey(), key.getKmsKeyId(), key.getRsaKey())) {
                throw new RuntimeException("KeyMaterial must be only one, non-null input!");
            }
            Keyring keyring;
            if (key.getAesKey() != null) {
                byte[] keyBytes = new byte[key.getAesKey().remaining()];
                key.getAesKey().get(keyBytes);
                
                AesKeyring.Builder aesBuilder = AesKeyring.builder()
                        .wrappingKey(new SecretKeySpec(keyBytes, "AES"))
                        .enableLegacyWrappingAlgorithms(input.getConfig().isEnableLegacyWrappingAlgorithms());
                
                // Add materials description if provided
                if (key.getMaterialsDescription() != null && !key.getMaterialsDescription().isEmpty()) {
                    MaterialsDescription.Builder matDescBuilder = MaterialsDescription.builder();
                    for (Map.Entry<String, String> entry : key.getMaterialsDescription().entrySet()) {
                        matDescBuilder.put(entry.getKey(), entry.getValue());
                    }
                    aesBuilder.materialsDescription(matDescBuilder.build());
                }
                
                keyring = aesBuilder.build();
            } else if (key.getRsaKey() != null) {
                try {
                    byte[] keyBytes = new byte[key.getRsaKey().remaining()];
                    key.getRsaKey().get(keyBytes);
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
                    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                            privateKey.getModulus(),
                            privateKey.getPublicExponent()
                    );

                    // Generate public key
                    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                    RsaKeyring.Builder rsaBuilder = RsaKeyring.builder()
                            .enableLegacyWrappingAlgorithms(input.getConfig().isEnableLegacyWrappingAlgorithms())
                            .wrappingKeyPair(PartialRsaKeyPair.builder()
                                    .publicKey(publicKey)
                                    .privateKey(privateKey).build());
                    
                    // Add materials description if provided
                    if (key.getMaterialsDescription() != null && !key.getMaterialsDescription().isEmpty()) {
                        MaterialsDescription.Builder matDescBuilder = MaterialsDescription.builder();
                        for (Map.Entry<String, String> entry : key.getMaterialsDescription().entrySet()) {
                            matDescBuilder.put(entry.getKey(), entry.getValue());
                        }
                        rsaBuilder.materialsDescription(matDescBuilder.build());
                    }
                    
                    keyring = rsaBuilder.build();
                } catch (NoSuchAlgorithmException | InvalidKeySpecException nse) {
                    throw GenericServerError.builder()
                            .message(nse.getMessage())
                            .build();
                }
            } else if (key.getKmsKeyId() != null) {
                keyring = KmsKeyring.builder()
                        .enableLegacyWrappingAlgorithms(input.getConfig().isEnableLegacyWrappingAlgorithms())
                        .wrappingKeyId(key.getKmsKeyId())
                        .build();
            } else {
                throw new RuntimeException("No KeyMaterial found!");
            }

            // Configure S3 client with adaptive retry for throttling
            RetryPolicy retryPolicy = RetryPolicy.builder()
                    .numRetries(5)
                    .throttlingBackoffStrategy(BackoffStrategy.defaultThrottlingStrategy())
                    .build();

            S3Client wrappedClient = S3Client.builder()
                    .overrideConfiguration(ClientOverrideConfiguration.builder()
                            .retryPolicy(retryPolicy)
                            .build())
                    .build();

            // V4-Improved server configuration
            S3EncryptionClient.Builder s3ClientBuilder = S3EncryptionClient.builderV4()
                    .wrappedClient(wrappedClient)
                    .keyring(keyring)
                    .enableLegacyWrappingAlgorithms(input.getConfig().isEnableLegacyWrappingAlgorithms())
                    .enableLegacyUnauthenticatedModes(input.getConfig().isEnableLegacyUnauthenticatedModes());

            // Client Creation
            boolean instFilePut = false;
            if (input.getConfig().getInstructionFileConfig() != null) {
                instFilePut = input.getConfig().getInstructionFileConfig().isEnableInstructionFilePutObject();
                s3ClientBuilder.instructionFileConfig(InstructionFileConfig.builder()
                        .instructionFileClient(S3Client.create())
                        .enableInstructionFilePutObject(instFilePut)
                        .build());
            }

            // Configure commitment policy if provided
            if (input.getConfig().getCommitmentPolicy() != null) {
                CommitmentPolicy policy = getCommitmentPolicy(input.getConfig().getCommitmentPolicy());
                s3ClientBuilder.commitmentPolicy(policy);
            }

            // Configure encryption algorithm if provided
            if (input.getConfig().getEncryptionAlgorithm() != null) {
                AlgorithmSuite algorithm = getAlgorithmSuite(input.getConfig().getEncryptionAlgorithm());
                s3ClientBuilder.encryptionAlgorithm(algorithm);
            }

            S3Client s3Client = s3ClientBuilder.build();

            UUID uuid = UUID.randomUUID();
            String uuidString = uuid.toString();
            clientCache_.put(uuidString, s3Client);
            keyringCache_.put(uuidString, keyring);
            return CreateClientOutput.builder()
                    .clientId(uuidString)
                    .build();
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String stackTrace = sw.toString();
            throw GenericServerError.builder()
                    .message(stackTrace)
                    .build();
        }
    }

    private static AlgorithmSuite getAlgorithmSuite(EncryptionAlgorithm input) {
        if (input.equals(EncryptionAlgorithm.ALG_AES_256_CBC_IV16_NO_KDF)) {
            return AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF;
        } else if (input.equals(EncryptionAlgorithm.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)) {
            return AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        } else if (input.equals(EncryptionAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)) {
            return AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
        } else {
            throw new RuntimeException("Unknown encryption algorithm: " + input);
        }
    }

    private static software.amazon.encryption.s3.CommitmentPolicy getCommitmentPolicy(software.amazon.encryption.s3.model.CommitmentPolicy input) {
        if (input.equals(software.amazon.encryption.s3.model.CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)) {
            return FORBID_ENCRYPT_ALLOW_DECRYPT;
        } else if (input.equals(software.amazon.encryption.s3.model.CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)) {
            return REQUIRE_ENCRYPT_ALLOW_DECRYPT;
        } else if (input.equals(software.amazon.encryption.s3.model.CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)) {
            return REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
        } else {
            throw new RuntimeException("Unknown commitment policy: " + input);
        }
    }
}
