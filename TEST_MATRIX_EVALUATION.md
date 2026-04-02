# S3 Encryption Client — Test Matrix Evaluation

Maps each test case from `TEST_MATRIX.md` to existing tests in the codebase.
"TODO" means no existing test was found for that case.

---

## Encryption (put_object) — Positive Cases

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| E1 | Default config, KmsKeyring, bytes body | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_simple_roundtrip_ascii_string[KC_GCM]` |
| E2 | Default config + EncryptionContext | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_encryption_context_roundtrip[KC_GCM]` |
| E3 | REQUIRE_ENCRYPT_ALLOW_DECRYPT + committing suite | ✅ Covered | Both | Unit: `test/test_default_algorithm_commitment.py::test_default_encryption_decryptable_with_require_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestCommittingObjectDecryptPolicies[writer=REQUIRE_ALLOW]` |
| E4 | GCM_IV12_NO_KDF + FORBID_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_simple_roundtrip_ascii_string[AES_GCM]` |
| E5 | BytesIO body | 🔄 In progress | Both | Unit: `test/test_encryption.py::TestContentEncryption::test_bytesio_body_encrypts_successfully`; Integration: `test/integration/test_i_s3_encryption.py::test_bytesio_body_roundtrip` |
| E6 | None / empty body | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_no_body_roundtrip` |
| E7 | Custom keyring | ❌ TODO | — | No integration test uses a user-implemented `AbstractKeyring` subclass |
| E8 | Custom CMM (no keyring) | ❌ TODO | — | No integration test provides a custom CMM directly |

---

## Decryption (get_object) — Positive Cases

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| D1 | V3 GCM_HKDF_COMMIT, REQUIRE_REQUIRE, header | ✅ Covered | Both | Unit: `test/test_key_commitment.py::test_require_require_allows_committing_decrypt`, `test/test_default_algorithm_commitment.py::test_default_encryption_decryptable_with_require_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestCommittingObjectDecryptPolicies::test_require_require_decrypts_committing` |
| D2 | V3 + EncryptionContext | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_encryption_context_roundtrip[KC_GCM]` |
| D3 | V3 + delayed auth | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_delayed_authentication_mode[delayed-auth]` and `test/integration/test_i_s3_encryption_streaming.py::test_delayed_auth_roundtrip[KC_GCM]` |
| D4 | V3, REQUIRE_ENCRYPT_ALLOW_DECRYPT | 🔄 In progress | Both | Unit: `test/test_key_commitment.py::TestCommitmentPolicy::test_require_encrypt_allow_decrypt_allows_committing_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestCommittingObjectDecryptPolicies::test_require_encrypt_allow_decrypt_decrypts_committing` |
| D5 | V3, FORBID_ENCRYPT_ALLOW_DECRYPT | 🔄 In progress | Both | Unit: `test/test_key_commitment.py::TestCommitmentPolicy::test_forbid_encrypt_allow_decrypt_allows_committing_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestCommittingObjectDecryptPolicies::test_forbid_encrypt_allow_decrypt_decrypts_committing` |
| D6 | V2 GCM, REQUIRE_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment.py::test_require_encrypt_allow_decrypt_allows_non_committing_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestNonCommittingObjectDecryptPolicies::test_require_encrypt_allow_decrypt_decrypts_non_committing` |
| D7 | V2 GCM, FORBID_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment.py::test_forbid_encrypt_allows_non_committing_decrypt`; Integration: `test/integration/test_i_key_commitment_policy.py::TestNonCommittingObjectDecryptPolicies::test_forbid_encrypt_allow_decrypt_decrypts_non_committing` |
| D8 | V1 CBC, legacy enabled, legacy wrapping enabled | ✅ Covered | Unit | `test/test_decryption.py::TestCBCDecryption::test_cbc_decryption_succeeds_when_legacy_enabled` |
| D9 | V1 CBC, FORBID_ENCRYPT_ALLOW_DECRYPT + legacy | ✅ Covered | Unit | Same as D8 (uses FORBID_ENCRYPT_ALLOW_DECRYPT) |
| D10 | V2 GCM via instruction file | ✅ Covered | Both | Unit: `test/test_pipelines.py::test_decrypt_v2_from_instruction_file`; Integration: `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_v2_instruction_file` |
| D11 | V3 via instruction file | ✅ Covered | Both | Unit: `test/test_pipelines.py::test_decrypt_v3_from_instruction_file`; Integration: `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_v3_instruction_file` |
| D12 | V2 instruction file, custom suffix | ✅ Covered | Both | Unit: `test/test_pipelines.py::test_decrypt_with_custom_instruction_file_suffix`; Integration: `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_v2_instruction_file_custom_suffix` |
| D13 | V3 + mismatched EncryptionContext | ✅ Covered | Both | Unit: `test/test_kms_keyring.py::TestKmsKeyringOnDecrypt::test_on_decrypt_fails_with_mismatched_encryption_context`; Integration: `test/integration/test_i_s3_encryption.py::test_encryption_context_mismatch` |

---

## Round-Trip Tests

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| RT1 | Default config, small body | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_simple_roundtrip_ascii_string[KC_GCM]` |
| RT2 | Default config + EncryptionContext | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_encryption_context_roundtrip[KC_GCM]` |
| RT3 | Large body (> 1 MB) | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_delayed_auth_large_object` (1 MB) and `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_large_v2_instruction_file_delayed_auth` (50 MB) |
| RT4 | Empty body (0 bytes) | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_empty_body_roundtrip` and `test/integration/test_i_s3_encryption.py::test_no_body_roundtrip` |
| RT5 | GCM_IV12_NO_KDF + FORBID | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_simple_roundtrip_ascii_string[AES_GCM]` |
| RT6 | Delayed authentication | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_delayed_auth_roundtrip` and `test/integration/test_i_s3_encryption.py::test_delayed_authentication_mode` |

---

## Negative / Validation Cases — Encryption

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| EN1 | Reject legacy suite for encryption | ✅ Covered | Unit | `test/test_key_commitment_encrypt.py` — legacy CBC rejected at config time |
| EN2 | GCM_IV12 + REQUIRE_ENCRYPT_REQUIRE_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment_encrypt.py::TestRequireEncryptRejectsNonCommitting::test_require_encrypt_require_decrypt_rejects_non_committing_gcm`; Integration: `test/integration/test_i_key_commitment_policy.py::TestEncryptPolicyRejection::test_require_encrypt_require_decrypt_rejects_non_committing` |
| EN3 | GCM_IV12 + REQUIRE_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment_encrypt.py::TestRequireEncryptRejectsNonCommitting::test_require_encrypt_allow_decrypt_rejects_non_committing_gcm`; Integration: `test/integration/test_i_key_commitment_policy.py::TestEncryptPolicyRejection::test_require_encrypt_allow_decrypt_rejects_non_committing` |
| EN4 | GCM_HKDF_COMMIT + FORBID_ENCRYPT_ALLOW_DECRYPT | ✅ Covered | Both | Unit: `test/test_key_commitment_encrypt.py::TestForbidEncryptRejectsCommitting::test_forbid_encrypt_allow_decrypt_rejects_committing_gcm`; Integration: `test/integration/test_i_key_commitment_policy.py::TestEncryptPolicyRejection::test_forbid_encrypt_allow_decrypt_rejects_committing` |

---

## Negative / Validation Cases — Decryption

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| DN1 | V1 CBC rejected when legacy disabled | ✅ Covered | Unit | `test/test_decryption.py::TestCBCDecryption::test_cbc_object_rejected_when_legacy_disabled` and `test/test_decryption.py::TestLegacyDecryption::test_legacy_cbc_rejected_by_default` |
| DN2 | V1 CBC, legacy enabled but legacy wrapping disabled | ✅ Covered | Unit | `test/test_kms_keyring.py::TestKmsKeyringOnDecrypt::test_on_decrypt_rejects_kms_v1_when_legacy_disabled` |
| DN3 | V2 non-committing + REQUIRE_REQUIRE | ✅ Covered | Both | Unit: `test/test_key_commitment.py::TestCommitmentPolicy::test_require_require_rejects_non_committing_decrypt` and `test/test_decryption.py::TestKeyCommitmentPolicy::test_require_decrypt_rejects_non_committing_suite`; Integration: `test/integration/test_i_key_commitment_policy.py::TestNonCommittingObjectDecryptPolicies::test_require_require_rejects_non_committing` |
| DN4 | Mismatched EncryptionContext | ✅ Covered | Both | Unit: `test/test_kms_keyring.py::TestKmsKeyringOnDecrypt::test_on_decrypt_fails_with_mismatched_encryption_context`; Integration: `test/integration/test_i_s3_encryption.py::test_encryption_context_mismatch` |
| DN5 | Reserved key in EncryptionContext | ✅ Covered | Unit | `test/test_kms_keyring.py::TestKmsKeyringOnDecrypt::test_on_decrypt_rejects_reserved_key_in_request_context` |

---

## Negative / Validation Cases — Instruction File

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| IF1 | Instruction file missing from S3 | 🔄 In progress | Unit | `test/test_pipelines.py::TestGetEncryptedObjectPipelineInstructionFile::test_decrypt_instruction_file_s3_not_found_raises` |
| IF2 | Instruction file contains invalid JSON | ✅ Covered | Both | Unit: `test/test_s3_encryption_client_plugin.py::test_instruction_file_mode_invalid_json_raises_error`; Integration: `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_invalid_instruction_file` |
| IF3 | Instruction file suffix mismatch | 🔄 In progress | Integration | `test/integration/test_i_s3_encryption_instruction_file.py::test_decrypt_instruction_file_wrong_suffix_raises` |
| IF4 | Instruction file exists but has no body | 🔄 In progress | Unit | `test/test_pipelines.py::TestGetEncryptedObjectPipelineInstructionFile::test_decrypt_instruction_file_empty_metadata_raises` |

---

## Negative / Validation Cases — General

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| G1 | Unsupported Body type | ✅ Covered | Integration | `test/integration/test_i_s3_encryption.py::test_invalid_body_types` |
| G2 | put_object in instruction-file mode | 🔄 In progress | Unit | `test/test_s3_encryption_client_plugin.py::TestS3EncryptionClientPlugin::test_put_object_rejects_instruction_file_mode` |
| G3 | Instruction file fetch with no s3_client | 🔄 In progress | Unit | `test/test_pipelines.py::TestGetEncryptedObjectPipelineInstructionFile::test_decrypt_instruction_file_no_s3_client_raises` |
| G4 | Instruction file fetch with missing Bucket/Key | 🔄 In progress | Unit | `test/test_pipelines.py::TestGetEncryptedObjectPipelineInstructionFile::test_decrypt_instruction_file_missing_bucket_key_raises` |

---

## Streaming / Delayed Authentication

| # | Description | Status | Type | Test Location |
|---|-------------|--------|------|---------------|
| S1 | Buffered withholds plaintext until tag verified | ✅ Covered | Unit | `test/test_stream.py::TestBufferedWithholdsUntilVerification::test_buffered_verifies_tag_before_releasing_any_plaintext` |
| S2 | Delayed auth releases plaintext before tag verification | ✅ Covered | Unit | `test/test_stream.py::TestDelayedAuthReleasesBeforeVerification::test_delayed_auth_releases_plaintext_before_tag_verification` |
| S3 | Both modes produce identical plaintext | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_buffered_and_delayed_produce_same_plaintext` |
| S4 | Chunked / partial reads | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_buffered_partial_reads` and `test_delayed_auth_chunked_reads` |
| S5 | Empty body round-trip both modes | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_empty_body_roundtrip` (parametrized buffered + delayed-auth) |
| S6 | Large object delayed-auth streaming | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_streaming.py::test_delayed_auth_large_object` (1 MB) |
| S7 | CBC always streams regardless of flag | ✅ Covered | Unit | `test/test_stream.py::TestDelayedAuthCBCDecryption` (full suite of CBC streaming tests) |
| S8 | Tampered ciphertext detected (buffered) | ✅ Covered | Unit | `test/test_stream.py::TestBufferedDecryptingStream::test_tampered_ciphertext_raises_error` |
| S9 | Tampered tag detected (delayed auth) | ✅ Covered | Unit | `test/test_stream.py::TestDelayedAuthGCMDecryption::test_tampered_tag_raises_error` |

---

## Cross-Cutting Concerns

| Concern | Status | Type | Test Location |
|---------|--------|------|---------------|
| Thread safety | ✅ Covered | Integration | `test/integration/test_i_s3_encryption_multithreaded.py` (3 tests: isolation, rapid switching, mixed) |
| Custom CMM | ❌ TODO | — | No end-to-end test with a user-provided CMM |
| Custom keyring | ❌ TODO | — | No end-to-end test with a user-implemented `AbstractKeyring` |
| Multi-region KMS keys | ❌ TODO | — | No test for cross-region encrypt/decrypt |
| Error propagation | ✅ Covered | Unit | `test/test_exceptions.py` (both error classes, inheritance from `BotoCoreError`) |
| Instruction file edge cases | 🔄 In progress | Both | Unit: invalid JSON, invalid keys, missing file, empty body; Integration: invalid instruction file; suffix mismatch is in progress|

---

## Summary

- Total test cases: 49 (E1–E8, D1–D13, RT1–RT6, EN1–EN4, DN1–DN5, IF1–IF4, G1–G4, S1–S9)
- Covered: 37
- In progress (this PR): 9 (E5, D4, D5, IF1, IF3, IF4, G2, G3, G4)
- TODO: 2 (E7, E8)
