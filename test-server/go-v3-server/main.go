package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/aws/amazon-s3-encryption-client-go/v3/client"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Server represents the Go test server
type Server struct {
	clientCache map[string]*client.S3EncryptionClientV3
	kmsClient   *kms.Client
}

// CreateClientInput represents the input for creating a client
type CreateClientInput struct {
	Config S3ECConfig `json:"config"`
}

// CreateClientOutput represents the output for creating a client
type CreateClientOutput struct {
	ClientID string `json:"clientId"`
}

// S3ECConfig represents the S3 encryption client configuration
type S3ECConfig struct {
	EnableLegacyUnauthenticatedModes bool        `json:"enableLegacyUnauthenticatedModes"`
	EnableDelayedAuthenticationMode  bool        `json:"enableDelayedAuthenticationMode"`
	EnableLegacyWrappingAlgorithms   bool        `json:"enableLegacyWrappingAlgorithms"`
	SetBufferSize                    int64       `json:"setBufferSize"`
	KeyMaterial                      KeyMaterial `json:"keyMaterial"`
}

// KeyMaterial represents the key material for encryption
type KeyMaterial struct {
	RSAKey   []byte `json:"rsaKey"`
	AESKey   []byte `json:"aesKey"`
	KMSKeyID string `json:"kmsKeyId"`
}

// PutObjectOutput represents the output for put object operation
type PutObjectOutput struct {
	Bucket   string   `json:"bucket"`
	Key      string   `json:"key"`
	Metadata []string `json:"metadata"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

// NewServer creates a new server instance
func NewServer() (*Server, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-west-2"))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &Server{
		clientCache: make(map[string]*client.S3EncryptionClientV3),
		kmsClient:   kms.NewFromConfig(cfg),
	}, nil
}

// createGenericServerError creates a generic server error response
func (s *Server) createGenericServerError(w http.ResponseWriter, message string, statusCode int) {
	// Echo error to console
	log.Printf("GenericServerError: %s (Status: %d)", message, statusCode)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Type:    "software.amazon.encryption.s3#GenericServerError",
		Message: message,
	})
}

// createS3EncryptionClientError creates an S3 encryption client error response
func (s *Server) createS3EncryptionClientError(w http.ResponseWriter, message string, statusCode int) {
	// Echo error to console
	log.Printf("S3EncryptionClientError: %s (Status: %d)", message, statusCode)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Type:    "software.amazon.encryption.s3#S3EncryptionClientError",
		Message: message,
	})
}

// metadataStringToMap converts metadata string to map
func metadataStringToMap(mdString string) (map[string]string, error) {
	md := make(map[string]string)
	if mdString == "" {
		return md, nil
	}

	mdList := strings.Split(mdString, ",")
	for _, entry := range mdList {
		// Split on "]:[" to separate key and value
		parts := strings.Split(entry, "]:[")
		if len(parts) == 2 {
			// Remove remaining brackets from start and end
			key := parts[0][1:]                 // Remove first character
			value := parts[1][:len(parts[1])-1] // Remove last character
			md[key] = value
		} else {
			return nil, fmt.Errorf("malformed metadata list entry: %s", entry)
		}
	}
	return md, nil
}

// createClient handles POST /client
func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	log.Printf("CreateClient: Received POST /client request")

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.createGenericServerError(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var input CreateClientInput
	if err := json.Unmarshal(body, &input); err != nil {
		s.createGenericServerError(w, "Invalid JSON in request body", http.StatusBadRequest)
		return
	}

	log.Printf("CreateClient: Parsed config - KMSKeyID: %s, EnableLegacyWrappingAlgorithms: %t",
		input.Config.KeyMaterial.KMSKeyID, input.Config.EnableLegacyWrappingAlgorithms)

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-west-2"))
	if err != nil {
		s.createS3EncryptionClientError(w, fmt.Sprintf("Failed to load AWS config: %v", err), http.StatusInternalServerError)
		return
	}

	// Create KMS keyring
	log.Printf("CreateClient: Creating KMS keyring with key ID: %s", input.Config.KeyMaterial.KMSKeyID)
	kmsClient := kms.NewFromConfig(cfg)
	keyring := materials.NewKmsKeyring(kmsClient, input.Config.KeyMaterial.KMSKeyID, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = input.Config.EnableLegacyWrappingAlgorithms
	})
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)

	if err != nil {
		s.createS3EncryptionClientError(w, fmt.Sprintf("Failed to create CMM: %v", err), http.StatusInternalServerError)
		return
	}

	// Create S3 encryption client
	log.Printf("CreateClient: Creating S3 encryption client")
	var s3EncryptionClient *client.S3EncryptionClientV3
	s3PlaintextClient := s3.NewFromConfig(cfg)
	s3EncryptionClient, err = client.New(s3PlaintextClient, cmm)

	if err != nil {
		s.createS3EncryptionClientError(w, fmt.Sprintf("Failed to create S3EC: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate client ID
	clientID := uuid.New().String()
	log.Printf("CreateClient: Generated client ID: %s", clientID)

	// Store client in cache
	s.clientCache[clientID] = s3EncryptionClient
	log.Printf("CreateClient: Stored client in cache. Total clients: %d", len(s.clientCache))

	// Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CreateClientOutput{
		ClientID: clientID,
	})
	log.Printf("CreateClient: Successfully created client %s", clientID)
}

// putObject handles PUT /object/{bucket}/{key}
func (s *Server) putObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	log.Printf("PutObject: Received PUT /object/%s/%s request", bucket, key)

	clientID := r.Header.Get("ClientID")
	if clientID == "" {
		s.createGenericServerError(w, "ClientID header is required", http.StatusBadRequest)
		return
	}

	log.Printf("PutObject: Using client ID: %s", clientID)

	// Get client from cache
	client, exists := s.clientCache[clientID]

	if !exists {
		s.createGenericServerError(w, fmt.Sprintf("No client found for ClientID: %s", clientID), http.StatusNotFound)
		return
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.createGenericServerError(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	log.Printf("PutObject: Read body of size: %d bytes", len(body))

	// Get metadata from header
	metadataHeader := r.Header.Get("Content-Metadata")
	encCtx, err := metadataStringToMap(metadataHeader)

	// Create context with encryption context
	ctx := context.Background()
	encryptionContext := context.WithValue(ctx, "EncryptionContext", encCtx)
	if err != nil {
		s.createS3EncryptionClientError(w, fmt.Sprintf("Failed to parse metadata: %v", err), http.StatusBadRequest)
		return
	}

	if len(encCtx) > 0 {
		metadataJSON, _ := json.Marshal(encCtx)
		log.Printf("PutObject: Using encryption context: %s", string(metadataJSON))
	} else {
		log.Printf("PutObject: No encryption context provided")
	}

	// Create put object input
	putInput := &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   strings.NewReader(string(body)),
	}

	// Add metadata if present
	if len(encCtx) > 0 {
		putInput.Metadata = encCtx
	}

	log.Printf("PutObject: Making S3 PutObject request")
	// Make the put object request using the encryption client
	_, err = client.PutObject(encryptionContext, putInput)
	if err != nil {
		s.createS3EncryptionClientError(w, fmt.Sprintf("Failed to put object: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("PutObject SUCCESS: Bucket=%s, Key=%s", bucket, key)

	// Return response
	w.Header().Set("Content-Type", "application/json")
	response := PutObjectOutput{
		Bucket:   bucket,
		Key:      key,
		Metadata: []string{}, // Return empty metadata list as per the model
	}
	json.NewEncoder(w).Encode(response)
	log.Printf("PutObject: Response sent successfully")
}

// getObject handles GET /object/{bucket}/{key}
func (s *Server) getObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	log.Printf("GetObject: Received GET /object/%s/%s request", bucket, key)

	clientID := r.Header.Get("ClientID")
	if clientID == "" {
		s.createGenericServerError(w, "ClientID header is required", http.StatusBadRequest)
		return
	}

	log.Printf("GetObject: Using client ID: %s", clientID)

	// Get client from cache
	client, exists := s.clientCache[clientID]

	if !exists {
		s.createGenericServerError(w, fmt.Sprintf("No client found for ClientID: %s", clientID), http.StatusNotFound)
		return
	}

	// Get metadata from header
	metadataHeader := r.Header.Get("Content-Metadata")
	encCtx, err := metadataStringToMap(metadataHeader)

	// Create context with encryption context
	// Note: S3EC Go V3 does not validate encryption context on decrypt, so the value provided here
	// will not be validated against the encryption context stored on the object.
	ctx := context.Background()
	encryptionContext := context.WithValue(ctx, "EncryptionContext", encCtx)
	if err != nil {
		s.createS3EncryptionClientError(w, fmt.Sprintf("Failed to parse metadata: %v", err), http.StatusBadRequest)
		return
	}

	if len(encCtx) > 0 {
		metadataJSON, _ := json.Marshal(encCtx)
		log.Printf("GetObject: Using encryption context: %s", string(metadataJSON))
	} else {
		log.Printf("GetObject: No encryption context provided")
	}

	// Create get object input
	getInput := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	log.Printf("GetObject: Making S3 GetObject request")
	// Make the get object request using the encryption client
	result, err := client.GetObject(encryptionContext, getInput)
	if err != nil {
		errMsg := err.Error()
		// Shim the S3EC error message to the error message expected by the test server.
		// We don't want to change the S3EC error message but the test server expects a specific error message;
		// This is the appropriate place to rewrite the error message.
		if strings.Contains(errMsg, "to decrypt x-amz-cek-alg value `kms` you must enable legacyWrappingAlgorithms on the keyring") {
			s.createS3EncryptionClientError(w, "Enable legacy wrapping algorithms to use legacy key wrapping algorithm: kms", http.StatusInternalServerError)
			return
		}
		s.createS3EncryptionClientError(w, fmt.Sprintf("Failed to get object: %v", err), http.StatusInternalServerError)
		return
	}
	defer result.Body.Close()

	// Read the body
	body, err := io.ReadAll(result.Body)
	if err != nil {
		s.createS3EncryptionClientError(w, fmt.Sprintf("Failed to read object body: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("GetObject: Read body of size: %d bytes", len(body))

	// Convert metadata to string format
	var metadataList []string
	if result.Metadata != nil {
		for k, v := range result.Metadata {
			metadataList = append(metadataList, fmt.Sprintf("%s=%s", k, v))
		}
	}

	metadataStr := strings.Join(metadataList, ",")

	if len(metadataList) > 0 {
		log.Printf("GetObject: Retrieved metadata: %s", metadataStr)
	} else {
		log.Printf("GetObject: No metadata found in object")
	}

	log.Printf("GetObject SUCCESS: Bucket=%s, Key=%s", bucket, key)
	log.Printf("GetObject: Body content: %s", string(body))

	// Set response headers
	w.Header().Set("Content-Metadata", metadataStr)

	// Return the body as response
	w.Write(body)
	log.Printf("GetObject: Response sent successfully")
}

func main() {
	server, err := NewServer()
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	r := mux.NewRouter()

	// Register routes
	r.HandleFunc("/client", server.createClient).Methods("POST")
	r.HandleFunc("/object/{bucket}/{key}", server.putObject).Methods("PUT")
	r.HandleFunc("/object/{bucket}/{key}", server.getObject).Methods("GET")

	fmt.Println("Starting Go server on :8082...")
	log.Fatal(http.ListenAndServe(":8082", r))
}
