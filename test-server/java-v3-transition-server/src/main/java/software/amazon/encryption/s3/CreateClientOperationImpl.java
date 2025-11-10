package software.amazon.encryption.s3;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.Keyring;
import software.amazon.encryption.s3.materials.KmsKeyring;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Map;
import java.util.UUID;

import static software.amazon.encryption.s3.CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT;
import static software.amazon.encryption.s3.CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT;
import static software.amazon.encryption.s3.CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

public class CreateClientOperationImpl implements CreateClientOperation {
    private Map<String, S3Client> clientCache_;

    public CreateClientOperationImpl(Map<String, S3Client> clientCache) {
        clientCache_ = clientCache;
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
                keyring = AesKeyring.builder()
                        .wrappingKey(new SecretKeySpec(keyBytes, "AES"))
                        .enableLegacyWrappingAlgorithms(input.getConfig().isEnableLegacyWrappingAlgorithms())
                        .build();
            } else if (key.getRsaKey() != null) {
                try {
                    byte[] keyBytes = new byte[key.getRsaKey().remaining()];
                    key.getRsaKey().get(keyBytes);
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    keyring = RsaKeyring.builder()
                            .enableLegacyWrappingAlgorithms(input.getConfig().isEnableLegacyWrappingAlgorithms())
                            .wrappingKeyPair(PartialRsaKeyPair.builder()
                                    .privateKey(keyFactory.generatePrivate(keySpec)).build())
                            .build();
                } catch (NoSuchAlgorithmException | InvalidKeySpecException nse) {
                    throw new RuntimeException(nse);
                }
            } else if (key.getKmsKeyId() != null) {
                keyring = KmsKeyring.builder()
                        .enableLegacyWrappingAlgorithms(input.getConfig().isEnableLegacyWrappingAlgorithms())
                        .wrappingKeyId(key.getKmsKeyId())
                        .build();
            } else {
                throw new RuntimeException("No KeyMaterial found!");
            }

            boolean instFilePut = false;
            if (input.getConfig().getInstructionFileConfig() != null) {
                instFilePut = input.getConfig().getInstructionFileConfig().isEnableInstructionFilePutObject();
            }

            // Configure commitment policy if provided
            software.amazon.encryption.s3.CommitmentPolicy policy = FORBID_ENCRYPT_ALLOW_DECRYPT;
            if (input.getConfig().getCommitmentPolicy() != null) {
                policy = getCommitmentPolicy(input.getConfig().getCommitmentPolicy());
            }

            // Configure encryption algorithm if provided
            AlgorithmSuite algorithm = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
            if (input.getConfig().getEncryptionAlgorithm() != null) {
                algorithm = getAlgorithmSuite(input.getConfig().getEncryptionAlgorithm());
            }

            // V3-Transitonal server configuration
            S3EncryptionClient s3Client = S3EncryptionClient.builderV4()
                    .instructionFileConfig(InstructionFileConfig.builder()
                            .instructionFileClient(S3Client.create())
                            .enableInstructionFilePutObject(instFilePut)
                            .build())
                    .keyring(keyring)
                    .commitmentPolicy(policy)
                    .encryptionAlgorithm(algorithm)
                    .enableLegacyWrappingAlgorithms(input.getConfig().isEnableLegacyWrappingAlgorithms())
                    .enableLegacyUnauthenticatedModes(input.getConfig().isEnableLegacyUnauthenticatedModes())
                    .build();

            UUID uuid = UUID.randomUUID();
            String uuidString = uuid.toString();
            clientCache_.put(uuidString, s3Client);
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
