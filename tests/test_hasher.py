"""
Unit tests for compute_sha256_standalone (imported from main.py).
"""

import pytest

from main import compute_sha256_standalone

# Precomputed independently: python -c "import hashlib; ..."
# echo -n 'WhatsApp Forensic Tool - deterministic test payload for SHA-256\n' | sha256sum
KNOWN_CONTENT_EXPECTED_SHA256 = (
    "b62ecae3d20a40217eae9ff48aed31b56ab05270fdfd52822ad9065965728ded"
)

EMPTY_FILE_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)


class TestComputeSha256KnownContent:
    def test_compute_sha256_matches_precomputed_hash(
        self, known_content_file, known_content_sha256
    ):
        result = compute_sha256_standalone(str(known_content_file))
        assert result == known_content_sha256
        assert result == KNOWN_CONTENT_EXPECTED_SHA256


class TestComputeSha256Consistency:
    def test_compute_sha256_is_consistent_across_repeated_calls(
        self, known_content_file, known_content_sha256
    ):
        first = compute_sha256_standalone(str(known_content_file))
        second = compute_sha256_standalone(str(known_content_file))
        assert first == second == known_content_sha256


class TestComputeSha256EmptyFile:
    def test_compute_sha256_empty_file_returns_known_empty_hash(self, empty_file):
        result = compute_sha256_standalone(str(empty_file))
        assert result == EMPTY_FILE_SHA256


class TestComputeSha256MissingFile:
    def test_compute_sha256_raises_file_not_found_for_missing_path(self, tmp_path):
        missing = tmp_path / "does_not_exist.bin"
        assert not missing.exists()

        with pytest.raises(FileNotFoundError):
            compute_sha256_standalone(str(missing))
