"""Tests for AbuseIPDB API client."""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime
import httpx

from mcp_abuseipdb.client_abuseipdb import AbuseIPDBClient
from mcp_abuseipdb.settings import Settings
from mcp_abuseipdb.models import IPCheckResponse, BlockCheckResponse, BlacklistResponse, APIError


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    return Settings(
        abuseipdb_api_key="test_api_key_12345",
        abuseipdb_base_url="https://api.abuseipdb.com/api/v2",
        request_timeout=30,
        max_retries=3
    )


@pytest.fixture
def sample_ip_check_response():
    """Sample successful IP check response."""
    return {
        "data": {
            "ipAddress": "8.8.8.8",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidencePercentage": 0,
            "countryCode": "US",
            "countryName": "United States",
            "usageType": "hosting",
            "isp": "Google LLC",
            "domain": "google.com",
            "totalReports": 0,
            "numDistinctUsers": 0,
            "lastReportedAt": None
        }
    }


@pytest.fixture
def sample_block_check_response():
    """Sample successful block check response."""
    return {
        "data": {
            "networkAddress": "203.0.113.0",
            "netmask": "24",
            "minAddress": "203.0.113.0",
            "maxAddress": "203.0.113.255",
            "numPossibleHosts": 256,
            "addressSpaceDesc": "Public Address Space",
            "reportedAddress": [
                {
                    "ipAddress": "203.0.113.100",
                    "abuseConfidencePercentage": 85,
                    "totalReports": 15,
                    "countryCode": "US"
                }
            ]
        }
    }


@pytest.fixture
def sample_blacklist_response():
    """Sample successful blacklist response."""
    return {
        "generatedAt": "2024-01-10T10:00:00Z",
        "data": [
            {
                "ipAddress": "203.0.113.100",
                "countryCode": "US",
                "abuseConfidencePercentage": 95,
                "lastReportedAt": "2024-01-10T09:00:00Z"
            }
        ]
    }


class TestAbuseIPDBClient:
    """Test cases for AbuseIPDBClient."""

    def test_client_initialization(self, mock_settings):
        """Test client initialization with settings."""
        client = AbuseIPDBClient(mock_settings)

        assert client.base_url == "https://api.abuseipdb.com/api/v2"
        assert client.api_key == "test_api_key_12345"
        assert client.timeout == 30

    @pytest.mark.asyncio
    async def test_client_context_manager(self, mock_settings):
        """Test client as async context manager."""
        async with AbuseIPDBClient(mock_settings) as client:
            assert isinstance(client, AbuseIPDBClient)
            assert client.client is not None

    def test_handle_response_success(self, mock_settings):
        """Test handling successful HTTP response."""
        client = AbuseIPDBClient(mock_settings)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"test": "value"}}

        result = client._handle_response(mock_response)
        assert result == {"data": {"test": "value"}}

    def test_handle_response_invalid_json(self, mock_settings):
        """Test handling response with invalid JSON."""
        client = AbuseIPDBClient(mock_settings)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)

        with pytest.raises(APIError) as exc_info:
            client._handle_response(mock_response)

        assert exc_info.value.error == "Invalid JSON response"
        assert exc_info.value.retryable is False

    def test_handle_response_401_unauthorized(self, mock_settings):
        """Test handling 401 Unauthorized response."""
        client = AbuseIPDBClient(mock_settings)

        mock_response = MagicMock()
        mock_response.status_code = 401

        with pytest.raises(APIError) as exc_info:
            client._handle_response(mock_response)

        assert exc_info.value.error == "Unauthorized - check API key"
        assert exc_info.value.status_code == 401
        assert exc_info.value.retryable is False

    def test_handle_response_403_forbidden(self, mock_settings):
        """Test handling 403 Forbidden response."""
        client = AbuseIPDBClient(mock_settings)

        mock_response = MagicMock()
        mock_response.status_code = 403

        with pytest.raises(APIError) as exc_info:
            client._handle_response(mock_response)

        assert exc_info.value.error == "Forbidden - API key may lack permissions"
        assert exc_info.value.retryable is False

    def test_handle_response_429_rate_limit(self, mock_settings):
        """Test handling 429 Rate Limit response."""
        client = AbuseIPDBClient(mock_settings)

        mock_response = MagicMock()
        mock_response.status_code = 429

        with pytest.raises(APIError) as exc_info:
            client._handle_response(mock_response)

        assert exc_info.value.error == "Rate limit exceeded"
        assert exc_info.value.retryable is True

    def test_handle_response_500_server_error(self, mock_settings):
        """Test handling 500 Server Error response."""
        client = AbuseIPDBClient(mock_settings)

        mock_response = MagicMock()
        mock_response.status_code = 500

        with pytest.raises(APIError) as exc_info:
            client._handle_response(mock_response)

        assert exc_info.value.error == "Server error"
        assert exc_info.value.retryable is True

    def test_handle_response_400_client_error(self, mock_settings):
        """Test handling 400 Client Error with error details."""
        client = AbuseIPDBClient(mock_settings)

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "errors": [{"detail": "Invalid IP address"}]
        }

        with pytest.raises(APIError) as exc_info:
            client._handle_response(mock_response)

        assert exc_info.value.error == "Invalid IP address"
        assert exc_info.value.retryable is False

    @pytest.mark.asyncio
    async def test_check_ip_success(self, mock_settings, sample_ip_check_response):
        """Test successful IP check."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = sample_ip_check_response
            mock_client.request.return_value = mock_response

            client = AbuseIPDBClient(mock_settings)
            result = await client.check_ip("8.8.8.8", max_age_days=30, verbose=False)

            assert isinstance(result, IPCheckResponse)
            assert result.ip_address == "8.8.8.8"
            assert result.abuse_confidence_percentage == 0

            # Verify request parameters
            mock_client.request.assert_called_once_with(
                "GET",
                "/check",
                params={
                    "ipAddress": "8.8.8.8",
                    "maxAgeInDays": 30,
                    "verbose": "false"
                }
            )

    @pytest.mark.asyncio
    async def test_check_ip_verbose(self, mock_settings, sample_ip_check_response):
        """Test IP check with verbose flag."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = sample_ip_check_response
            mock_client.request.return_value = mock_response

            client = AbuseIPDBClient(mock_settings)
            await client.check_ip("8.8.8.8", verbose=True)

            # Verify verbose parameter
            call_args = mock_client.request.call_args
            assert call_args[1]["params"]["verbose"] == "true"

    @pytest.mark.asyncio
    async def test_check_block_success(self, mock_settings, sample_block_check_response):
        """Test successful block check."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = sample_block_check_response
            mock_client.request.return_value = mock_response

            client = AbuseIPDBClient(mock_settings)
            result = await client.check_block("203.0.113.0/24", max_age_days=30)

            assert isinstance(result, BlockCheckResponse)
            assert result.network_address == "203.0.113.0"
            assert result.netmask == "24"

            # Verify request parameters
            mock_client.request.assert_called_once_with(
                "GET",
                "/check-block",
                params={
                    "network": "203.0.113.0/24",
                    "maxAgeInDays": 30
                }
            )

    @pytest.mark.asyncio
    async def test_get_blacklist_success(self, mock_settings, sample_blacklist_response):
        """Test successful blacklist retrieval."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = sample_blacklist_response
            mock_client.request.return_value = mock_response

            client = AbuseIPDBClient(mock_settings)
            result = await client.get_blacklist(confidence_minimum=90, limit=100)

            assert isinstance(result, BlacklistResponse)
            assert len(result.data) == 1
            assert result.data[0].ip_address == "203.0.113.100"

            # Verify request parameters
            mock_client.request.assert_called_once_with(
                "GET",
                "/blacklist",
                params={
                    "confidenceMinimum": 90,
                    "limit": 100
                }
            )

    @pytest.mark.asyncio
    async def test_get_blacklist_no_limit(self, mock_settings, sample_blacklist_response):
        """Test blacklist retrieval without limit."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = sample_blacklist_response
            mock_client.request.return_value = mock_response

            client = AbuseIPDBClient(mock_settings)
            await client.get_blacklist(confidence_minimum=90)

            # Verify no limit parameter
            call_args = mock_client.request.call_args
            assert "limit" not in call_args[1]["params"]

    @pytest.mark.asyncio
    async def test_make_request_timeout_retry(self, mock_settings):
        """Test request retry on timeout."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            # First call times out, second succeeds
            mock_client.request.side_effect = [
                httpx.TimeoutException("Request timeout"),
                MagicMock(status_code=200, json=lambda: {"data": {}})
            ]

            client = AbuseIPDBClient(mock_settings)
            result = await client._make_request("GET", "/test")

            assert result == {"data": {}}
            assert mock_client.request.call_count == 2

    @pytest.mark.asyncio
    async def test_make_request_api_error_no_retry(self, mock_settings):
        """Test that APIError is not retried."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_client.request.return_value = mock_response

            client = AbuseIPDBClient(mock_settings)

            with pytest.raises(APIError):
                await client._make_request("GET", "/test")

            # Should not retry on API error
            assert mock_client.request.call_count == 1

    @pytest.mark.asyncio
    async def test_make_request_unexpected_error(self, mock_settings):
        """Test handling of unexpected errors."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            mock_client.request.side_effect = ValueError("Unexpected error")

            client = AbuseIPDBClient(mock_settings)

            with pytest.raises(APIError) as exc_info:
                await client._make_request("GET", "/test")

            assert exc_info.value.error == "Request failed"
            assert "Unexpected error" in exc_info.value.details

    @pytest.mark.asyncio
    async def test_close_client(self, mock_settings):
        """Test closing the client."""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            client = AbuseIPDBClient(mock_settings)
            await client.close()

            mock_client.aclose.assert_called_once()