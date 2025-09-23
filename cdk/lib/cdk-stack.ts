import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  Alias,
  Key
} from "aws-cdk-lib/aws-kms";
import {
  Effect,
  Role,
  PolicyDocument,
  PolicyStatement,
  FederatedPrincipal,
  ManagedPolicy,
} from "aws-cdk-lib/aws-iam";
import { 
  BlockPublicAccess,
  BlockPublicAccessOptions,
  Bucket,
} from 'aws-cdk-lib/aws-s3';

export class S3ECPythonGithub extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    
    // KMS Keys - default policy is fine,
    // we use IAM to manage key permissions
    const S3ECGithubKMSKey = new Key(
      this,
      "S3ECGithubKMSKey",
      {
        enableKeyRotation: true,
        description: "KMS Key for GitHub Action Workflow",
      }
    )

    // KMS alias
    const S3ECGithubKMSKeyAlias = new Alias(
      this,
      "S3ECGithubKMSKeyAlias",
      {
        aliasName: "alias/S3EC-Python-Github-KMS-Key",
        targetKey: S3ECGithubKMSKey
      }
    )
    
    // KMS Key for test-server
    const S3ECTestServerKMSKey = new Key(
      this,
      "S3ECTestServerKMSKey",
      {
        enableKeyRotation: true,
        description: "KMS Key for Test Server GitHub Action Workflow",
      }
    )

    // KMS alias for test-server
    const S3ECTestServerKMSKeyAlias = new Alias(
      this,
      "S3ECTestServerKMSKeyAlias",
      {
        aliasName: "alias/S3EC-Test-Server-Github-KMS-Key",
        targetKey: S3ECTestServerKMSKey
      }
    )

    // S3 buckets
    const AccessConfiguration: BlockPublicAccessOptions = {
      blockPublicAcls: false,
      blockPublicPolicy: false,
      ignorePublicAcls: false,
      restrictPublicBuckets: false
    }
    const S3ECGithubTestS3Bucket = new Bucket(
      this,
      "S3ECGithubTestS3Bucket",
      {
        bucketName: "s3ec-python-github-test-bucket-" + this.account, // revert this
        blockPublicAccess: new BlockPublicAccess(AccessConfiguration)
      }
    )
    
    // New bucket for test-server
    const S3ECTestServerGithubBucket = new Bucket(
      this,
      "S3ECTestServerGithubBucket",
      {
        bucketName: "s3ec-test-server-github-bucket-" + this.account, // revert this
        blockPublicAccess: new BlockPublicAccess(AccessConfiguration)
      }
    )

    // S3 bucket policy
    const S3ECGithubS3BucketPolicy = new ManagedPolicy(
      this,
      "S3EC-Python-Github-S3-Bucket-Policy",
      {
        document: new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion"
              ],
              resources: [
                S3ECGithubTestS3Bucket.bucketArn + "/*", // object-level permissions need this extra path
                S3ECTestServerGithubBucket.bucketArn + "/*", // Add permissions for the new test-server bucket
                "arn:aws:s3:::aws-net-sdk-*/*" // permission for object inside S3EC .net bucket
              ],
            }),
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: [
                "s3:CreateBucket",
                "s3:DeleteBucket",
                "s3:ListBucket",
                "s3:ListBucketVersions",
                "s3:GetBucketAcl"
              ],
              resources: [
                S3ECGithubTestS3Bucket.bucketArn,
                S3ECTestServerGithubBucket.bucketArn, // Add permissions for the new test-server bucket
                "arn:aws:s3:::aws-net-sdk-*", // permission for S3EC .net bucket
              ],
            }),
          ]
        }),
      }
    );

    // KMS key policy
    const S3ECGithubKMSKeyPolicy = new ManagedPolicy(
      this,
      "S3EC-Python-Github-KMS-Key-Policy",
      {
        document: new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: [
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyPair"
              ],
              resources: [
                S3ECGithubKMSKey.keyArn,
                S3ECTestServerKMSKey.keyArn, // Add access to the test-server KMS key
              ]
            })
          ]
        }),
      }
    )

    // IAM role 
    const GithubActionsPrincipal = new FederatedPrincipal(
      "arn:aws:iam::" + this.account + ":oidc-provider/token.actions.githubusercontent.com",
      {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": [
            "repo:aws/amazon-s3-encryption-client-python:*",
            "repo:aws/private-amazon-s3-encryption-client-dotnet-staging:*"
          ]
        }
      },
      "sts:AssumeRoleWithWebIdentity"
    )
    const S3ECGithubTestRole = new Role(
      this,
      "s3-github-test-role",
      {
        assumedBy: GithubActionsPrincipal,
        roleName: "S3EC-Python-Github-test-role",
        description: " Grant GitHub S3 put and get and KMS encrypt, decrypt, and generate access for testing",
        path: "/",
        managedPolicies: [S3ECGithubS3BucketPolicy, S3ECGithubKMSKeyPolicy]
      }
    );
  }
}
