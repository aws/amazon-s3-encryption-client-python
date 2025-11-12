package software.amazon.encryption.s3;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.model.GenericServerError;
import software.amazon.encryption.s3.model.GetObjectInput;
import software.amazon.encryption.s3.model.GetObjectOutput;
import software.amazon.encryption.s3.model.S3EncryptionClientError;
import software.amazon.encryption.s3.service.GetObjectOperation;
import software.amazon.smithy.java.server.RequestContext;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

import static software.amazon.encryption.s3.MetadataUtils.metadataListToMap;
import static software.amazon.encryption.s3.MetadataUtils.metadataMapToList;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;

public class GetObjectOperationImpl implements GetObjectOperation {
    private final Map<String, S3Client> clientCache_;

    public GetObjectOperationImpl(Map<String, S3Client> clientCache) {
        clientCache_ = clientCache;
    }

    @Override
    public GetObjectOutput getObject(GetObjectInput input, RequestContext context) {
        try {
            S3Client s3Client = clientCache_.get(input.getClientID());
            Map<String, String> ecMap = metadataListToMap(input.getMetadata());

            try {
                ResponseBytes<GetObjectResponse> resp = s3Client.getObjectAsBytes(builder -> builder
                        .bucket(input.getBucket())
                        .key(input.getKey())
                        .range(input.getRange())
                        .overrideConfiguration(withAdditionalConfiguration(ecMap)));

                List<String> mdAsList = metadataMapToList(resp.response().metadata());
                // Can't use asBB else it gets mad bc cant access backing array
                ByteBuffer bb = ByteBuffer.wrap(resp.asByteArray());
                GetObjectOutput output = GetObjectOutput.builder()
                        .body(bb)
                        .metadata(mdAsList)
                        .build();
                return output;
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
