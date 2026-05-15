Amazon S3 Encryption Client for Python
=======================================

The Amazon S3 Encryption Client for Python provides client-side encryption
for objects stored in Amazon S3. It wraps a standard boto3 S3 client and
transparently encrypts objects on upload and decrypts them on download.

.. toctree::
   :maxdepth: 2
   :caption: Contents

   api

Getting Started
---------------

.. code-block:: python

   import boto3
   from s3_encryption import S3EncryptionClient, S3EncryptionClientConfig
   from s3_encryption.materials.kms_keyring import KmsKeyring

   kms_client = boto3.client("kms", region_name="us-west-2")
   keyring = KmsKeyring(kms_client, "arn:aws:kms:us-west-2:123456789012:alias/my-key")

   s3_client = boto3.client("s3")
   config = S3EncryptionClientConfig(keyring=keyring)
   s3ec = S3EncryptionClient(s3_client, config)

   # Encrypt and upload
   s3ec.put_object(Bucket="my-bucket", Key="my-object", Body=b"secret data")

   # Download and decrypt
   response = s3ec.get_object(Bucket="my-bucket", Key="my-object")
   plaintext = response["Body"].read()

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
