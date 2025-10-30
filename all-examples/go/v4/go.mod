module github.com/aws/amazon-s3-encryption-client-python/all-examples/go/v4

go 1.21

require (
	github.com/aws/amazon-s3-encryption-client-go/v4 v4.0.0
	github.com/aws/aws-sdk-go-v2 v1.24.0
	github.com/aws/aws-sdk-go-v2/config v1.26.1
	github.com/aws/aws-sdk-go-v2/service/kms v1.27.4
	github.com/aws/aws-sdk-go-v2/service/s3 v1.47.5
)

// S3EC Go V4 is not released to pkg.go.dev as of writing.
// It is included as a submodule and referenced locally.
replace github.com/aws/amazon-s3-encryption-client-go/v4 => ./local-go-s3ec/v4
