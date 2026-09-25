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

.. note::

   **Stream Length vs. Plaintext Length**

   The ``ContentLength`` field in the response dictionary returned by ``get_object``
   reflects the length of the ciphertext stream stored in S3, which includes
   the cryptographic authentication tag (or padding in the case of CBC). Consequently,
   the stream's ``ContentLength`` is greater than the decrypted plaintext length.
   Callers must read the entire stream (e.g. ``response["Body"].read()``) to complete
   decryption and authentication verification rather than relying on ``ContentLength``
   as the plaintext length.


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
