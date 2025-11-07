package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/amazon-s3-encryption-client-go/v3/client"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	// Check command line arguments
	if len(os.Args) != 5 {
		fmt.Printf("Usage: %s <bucket-name> <object-key> <kms-key-id> <region>\n", os.Args[0])
		fmt.Printf("Example: %s avp-21638 s3ec-go-v3 arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01 us-east-2\n", os.Args[0])
		os.Exit(1)
	}

	bucketName := os.Args[1]
	objectKey := os.Args[2]
	kmsKeyID := os.Args[3]
	region := os.Args[4]

	fmt.Println("=== S3 Encryption Client v3 Example (Go) ===")
	fmt.Printf("Bucket: %s\n", bucketName)
	fmt.Printf("Object Key: %s\n", objectKey)
	fmt.Printf("KMS Key ID: %s\n", kmsKeyID)
	fmt.Printf("Region: %s\n", region)
	fmt.Println()

	// Test data for encryption
	testData := "Hello, World! This is a test message for S3 encryption client v3 in Go."
	fmt.Printf("Original data: %s\n", testData)
	fmt.Printf("Data length: %d bytes\n", len(testData))
	fmt.Println()

	fmt.Println("--- Initialize S3 Encryption Client v3 ---")

	// Create regular S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		os.Exit(1)
	}
	s3Client := s3.NewFromConfig(cfg)

	// Create KMS client
	kmsClient := kms.NewFromConfig(cfg)

	// Create KMS keyring
	keyring := materials.NewKmsKeyring(kmsClient, kmsKeyID)

	// Create Cryptographic Materials Manager
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		fmt.Printf("Error creating CMM: %v\n", err)
		os.Exit(1)
	}

	// Create S3 Encryption Client v3
	encryptionClient, err := client.New(s3Client, cmm)
	if err != nil {
		fmt.Printf("Error creating S3 Encryption Client: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully initialized S3 Encryption Client v3")
	fmt.Println("--- Encrypt and Upload Object to S3 ---")

	// Add encryption context for additional security
	encryptionContext := map[string]string{
		"purpose":  "example",
		"version":  "v3",
		"language": "go",
	}

	// Create context with encryption context
	ctx := context.WithValue(context.Background(), "EncryptionContext", encryptionContext)

	// Upload encrypted object using S3 Encryption Client
	putInput := &s3.PutObjectInput{
		Bucket:   aws.String(bucketName),
		Key:      aws.String(objectKey),
		Body:     strings.NewReader(testData),
		Metadata: encryptionContext,
	}

	_, err = encryptionClient.PutObject(ctx, putInput)
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchBucket") {
			fmt.Printf("Error: S3 bucket '%s' does not exist or is not accessible\n", bucketName)
		} else if strings.Contains(err.Error(), "NotFoundException") {
			fmt.Printf("Error: KMS key '%s' not found or not accessible\n", kmsKeyID)
		} else {
			fmt.Printf("Error uploading encrypted object: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Println("Successfully uploaded encrypted object to S3!")
	fmt.Printf("   Bucket: %s\n", bucketName)
	fmt.Printf("   Key: %s\n", objectKey)
	fmt.Printf("   Encryption Context: %v\n", encryptionContext)
	fmt.Println()

	fmt.Println("--- Download and Decrypt Object from S3 ---")

	// Download and decrypt object using S3 Encryption Client
	getInput := &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	}

	getResponse, err := encryptionClient.GetObject(ctx, getInput)
	if err != nil {
		fmt.Printf("Error downloading and decrypting object: %v\n", err)
		os.Exit(1)
	}
	defer getResponse.Body.Close()

	// Read the decrypted data
	decryptedData, err := io.ReadAll(getResponse.Body)
	if err != nil {
		fmt.Printf("Error reading decrypted data: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully downloaded and decrypted object from S3!")
	fmt.Printf("   Object size: %d bytes\n", len(decryptedData))
	fmt.Printf("   Decrypted data: %s\n", string(decryptedData))
	fmt.Println()

	fmt.Println("--- Verify Roundtrip Success ---")

	// Verify the roundtrip was successful
	if string(decryptedData) == testData {
		fmt.Println("SUCCESS: Roundtrip encryption/decryption completed successfully!")
		fmt.Println("   Original data matches decrypted data")
		fmt.Println("   Data integrity verified")
	} else {
		fmt.Println("ERROR: Roundtrip failed - data mismatch")
		fmt.Printf("   Original: %s\n", testData)
		fmt.Printf("   Decrypted: %s\n", string(decryptedData))
		os.Exit(1)
	}

	// Optionally Delete the Object
	//fmt.Println("--- Cleanup ---")
	// Clean up the test object using regular S3 client
	// _, err = s3Client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
	// 	Bucket: aws.String(bucketName),
	// 	Key:    aws.String(objectKey),
	// })
	// if err != nil {
	// 	fmt.Printf("Error deleting test object: %v\n", err)
	// } else {
	// 	fmt.Println("Test object deleted from S3")
	// }

	fmt.Println()
	fmt.Println("=== Example completed successfully! ===")
}
