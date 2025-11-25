package software.amazon.encryption.s3;

import software.amazon.awssdk.core.traits.Trait;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.Keyring;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RsaKeyring;
import software.amazon.smithy.java.core.schema.Schema;
import software.amazon.smithy.java.server.RequestContext;
import software.amazon.encryption.s3.model.CreateClientInput;
import software.amazon.encryption.s3.model.CreateClientOutput;
import software.amazon.encryption.s3.model.GenericServerError;
import software.amazon.encryption.s3.model.KeyMaterial;
import software.amazon.encryption.s3.service.CreateClientOperation;

import javax.crypto.spec.SecretKeySpec;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

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
      // Key Material / Keyring Creation
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
          RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
          RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
            privateKey.getModulus(),
            privateKey.getPublicExponent()
          );

          // Generate public key
          PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

          keyring = RsaKeyring.builder()
            .enableLegacyWrappingAlgorithms(input.getConfig().isEnableLegacyWrappingAlgorithms())
            .wrappingKeyPair(PartialRsaKeyPair.builder()
              .publicKey(publicKey)
              .privateKey(privateKey).build())
            .build();
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

      // Client Creation
      boolean instFilePut = false;
      if (input.getConfig().getInstructionFileConfig() != null) {
        instFilePut = input.getConfig().getInstructionFileConfig().isEnableInstructionFilePutObject();
      }
      S3Client s3Client = S3EncryptionClient.builder()
        .instructionFileConfig(InstructionFileConfig.builder()
          .instructionFileClient(S3Client.create())
          .enableInstructionFilePutObject(instFilePut)
          .build())
        .keyring(keyring)
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
}
