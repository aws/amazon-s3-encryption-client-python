# S3 Encryption Client Examples

This directory contains example projects for the Amazon S3 Encryption Client across different programming languages and major versions.

## Directory Structure

Each language has subdirectories for different major versions of the S3 Encryption Client:

- `cpp/` - C++ examples
  - `v2/` - S3EC C++ v2 example (transitional)
  - `v3/` - S3EC C++ v3 example (improved)
- `dotnet/` - .NET examples
  - `v3/` - S3EC .NET v3 example (transitional)
  - `v4/` - S3EC .NET v4 example (improved)
- `go/` - Go examples
  - `v3/` - S3EC Go v3 example (transitional)
  - `v4/` - S3EC Go v4 example (improved)
- `java/` - Java examples
  - `v3/` - S3EC Java v3 example (transitional)
  - `v4/` - S3EC Java v4 example (improved)
- `php/` - PHP examples
  - `v2/` - S3EC PHP v2 example (transitional)
  - `v3/` - S3EC PHP v3 example (improved)
- `ruby/` - Ruby examples
  - `v2/` - S3EC Ruby v2 example (transitional)
  - `v3/` - S3EC Ruby v3 example (improved)

## Setup Instructions

### Prerequisites

1. **Git Submodules**: Some examples depend on staging versions of the S3EC libraries that are included as git submodules. Initialize and update submodules:

   ```bash
   git submodule update --init --recursive
   ```

2. **AWS Credentials**: Configure your AWS credentials using one of the following methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - IAM roles (for EC2 instances)

3. **KMS Key**: Use "arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01" by default, or create a KMS key in your AWS account and note the key ID for use in examples.

### Language-Specific Setup

Each language directory contains specific setup instructions in its README file. Generally:

- **Java**: Requires JDK 11+ and Gradle
- **Go**: Requires Go 1.21+
- **.NET**: Requires .NET 8.0+
- **PHP**: Requires PHP 7.4+ and Composer
- **Ruby**: Requires Ruby 3.0+ and Bundler
- **C++**: Requires CMake 3.16+ and C++17 compiler

## Usage

Each example directory contains:

- Build configuration files (e.g., `build.gradle.kts`, `go.mod`, `composer.json`)
- Source code demonstrating basic S3EC usage
- README with specific setup and run instructions

## Dependencies

Examples use different dependency sources based on version:

- **Released versions**: Use public package repositories (Maven Central, npm, etc.)
- **Staging versions**: Use git submodules pointing to staging repositories
- **Local versions**: Reference locally built libraries

## Support

For issues with specific examples, refer to the individual README files in each language/version directory.
