package software.amazon.encryption.s3;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.encryption.s3.model.GenericServerError;
import software.amazon.encryption.s3.model.PutObjectInput;
import software.amazon.encryption.s3.model.PutObjectOutput;
import software.amazon.encryption.s3.service.PutObjectOperation;
import software.amazon.smithy.java.server.RequestContext;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;

import static software.amazon.encryption.s3.MetadataUtils.metadataListToMap;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;

public class PutObjectOperationImpl implements PutObjectOperation {

    private final Map<String, S3Client> clientCache_;

    public PutObjectOperationImpl(Map<String, S3Client> clientCache) {
        clientCache_ = clientCache;
    }

    @Override
    public PutObjectOutput putObject(PutObjectInput input, RequestContext context) {
        try {
            final Map<String, String> metadata = metadataListToMap(input.getMetadata());
            S3Client s3Client = clientCache_.get(input.getClientID());
            s3Client.putObject(builder -> builder
                            .bucket(input.getBucket())
                            .key(input.getKey())
                            .overrideConfiguration(withAdditionalConfiguration(metadata)),
                    RequestBody.fromByteBuffer(input.getBody())
            );
            // The real S3 doesn't provide bucket/key/metadata, so Test doesn't need to either, but we do anyway
            return PutObjectOutput.builder()
                    .bucket(input.getBucket())
                    .key(input.getKey())
                    .metadata(input.getMetadata())
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
