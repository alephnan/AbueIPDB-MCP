"""Tests for get_blacklist tool."""

import pytest
from unittest.mock import AsyncMock
from datetime import datetime
from mcp.types import CallToolResult

from mcp_abuseipdb.tools.get_blacklist import GetBlacklistTool
from mcp_abuseipdb.settings import Settings
from mcp_abuseipdb.cache import CacheManager, RateLimiter
from mcp_abuseipdb.models import BlacklistResponse, BlacklistEntry


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    return Settings(
        abuseipdb_api_key="test_key",
        blacklist_confidence_min=90,
        confidence_threshold=75
    )


@pytest.fixture
def mock_cache():
    """Mock cache manager."""
    cache = AsyncMock(spec=CacheManager)
    cache.get.return_value = None
    cache.set = AsyncMock()
    cache.create_cache_key.return_value = "test_key"
    return cache


@pytest.fixture
def mock_rate_limiter():
    """Mock rate limiter."""
    limiter = AsyncMock(spec=RateLimiter)
    limiter.acquire.return_value = True
    return limiter


@pytest.fixture
def get_blacklist_tool(mock_settings, mock_cache, mock_rate_limiter):
    """Create GetBlacklistTool instance for testing."""
    return GetBlacklistTool(mock_settings, mock_cache, mock_rate_limiter)


@pytest.fixture
def sample_blacklist_response():
    """Sample blacklist response."""
    return {
        "generated_at": datetime.now(),
        "data": [
            {
                "ip_address": "203.0.113.100",
                "country_code": "US",
                "abuse_confidence_percentage": 95,
                "last_reported_at": datetime.now()
            },
            {
                "ip_address": "198.51.100.50",
                "country_code": "DE",
                "abuse_confidence_percentage": 92,
                "last_reported_at": datetime.now()
            },
            {
                "ip_address": "192.0.2.25",
                "country_code": "FR",
                "abuse_confidence_percentage": 88,
                "last_reported_at": datetime.now()
            },
            {
                "ip_address": "203.0.113.200",
                "country_code": "US",
                "abuse_confidence_percentage": 96,
                "last_reported_at": datetime.now()
            }
        ]
    }


class TestGetBlacklistTool:
    """Test cases for GetBlacklistTool."""

    @pytest.mark.asyncio
    async def test_get_tool_definition(self, get_blacklist_tool):
        """Test tool definition generation."""
        definition = await get_blacklist_tool.get_tool_definition()

        assert definition.name == "get_blacklist"
        assert "blacklist" in definition.description.lower()
        assert "confidence_minimum" in definition.inputSchema["properties"]
        assert "limit" in definition.inputSchema["properties"]
        assert definition.inputSchema["required"] == []

    @pytest.mark.asyncio
    async def test_execute_default_parameters(self, get_blacklist_tool, mock_cache, sample_blacklist_response):
        """Test execution with default parameters."""
        mock_cache.get.return_value = sample_blacklist_response

        result = await get_blacklist_tool.execute({})

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "4" in content  # 4 entries
        assert "90%" in content  # default confidence minimum

    @pytest.mark.asyncio
    async def test_execute_custom_confidence(self, get_blacklist_tool, mock_cache, sample_blacklist_response):
        """Test execution with custom confidence minimum."""
        mock_cache.get.return_value = sample_blacklist_response

        result = await get_blacklist_tool.execute({"confidence_minimum": 85})

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "85%" in content  # custom confidence minimum

    @pytest.mark.asyncio
    async def test_execute_with_limit(self, get_blacklist_tool, mock_cache, sample_blacklist_response):
        """Test execution with limit parameter."""
        mock_cache.get.return_value = sample_blacklist_response

        result = await get_blacklist_tool.execute({
            "confidence_minimum": 90,
            "limit": 100
        })

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "100" in content  # limit mentioned

    @pytest.mark.asyncio
    async def test_execute_invalid_confidence(self, get_blacklist_tool):
        """Test execution with invalid confidence minimum."""
        result = await get_blacklist_tool.execute({"confidence_minimum": 150})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "confidence_minimum must be between 0 and 100" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_invalid_limit(self, get_blacklist_tool):
        """Test execution with invalid limit."""
        result = await get_blacklist_tool.execute({"limit": 15000})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "limit must be between 1 and 10000" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_rate_limit_exceeded(self, get_blacklist_tool, mock_rate_limiter):
        """Test execution when rate limit is exceeded."""
        mock_rate_limiter.acquire.return_value = False

        result = await get_blacklist_tool.execute({})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "Rate limit exceeded" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_cache_hit(self, get_blacklist_tool, mock_cache, sample_blacklist_response):
        """Test execution with cache hit."""
        mock_cache.get.return_value = sample_blacklist_response

        result = await get_blacklist_tool.execute({"confidence_minimum": 90})

        # Verify cache was checked
        mock_cache.get.assert_called_once()
        mock_cache.set.assert_not_called()  # Should not set cache on hit

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

    @pytest.mark.asyncio
    async def test_execute_country_statistics(self, get_blacklist_tool, mock_cache, sample_blacklist_response):
        """Test country statistics generation."""
        mock_cache.get.return_value = sample_blacklist_response

        result = await get_blacklist_tool.execute({})

        content = result.content[0].text
        assert "Top Countries:" in content
        assert "US:" in content  # US appears twice in sample data
        assert "DE:" in content  # Germany appears once
        assert "FR:" in content  # France appears once

    @pytest.mark.asyncio
    async def test_execute_confidence_distribution(self, get_blacklist_tool, mock_cache, sample_blacklist_response):
        """Test confidence distribution calculation."""
        mock_cache.get.return_value = sample_blacklist_response

        result = await get_blacklist_tool.execute({})

        content = result.content[0].text
        assert "Confidence Distribution:" in content
        assert "90-100%" in content  # All sample entries are in this range

    @pytest.mark.asyncio
    async def test_execute_sample_entries_display(self, get_blacklist_tool, mock_cache, sample_blacklist_response):
        """Test sample entries display."""
        mock_cache.get.return_value = sample_blacklist_response

        result = await get_blacklist_tool.execute({})

        content = result.content[0].text
        assert "Sample Entries:" in content
        assert "203.0.113.100" in content  # First IP should be shown
        assert "198.51.100.50" in content  # Second IP should be shown

    @pytest.mark.asyncio
    async def test_execute_empty_blacklist(self, get_blacklist_tool, mock_cache):
        """Test execution with empty blacklist."""
        empty_response = {
            "generated_at": datetime.now(),
            "data": []
        }
        mock_cache.get.return_value = empty_response

        result = await get_blacklist_tool.execute({})

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "0" in content  # 0 entries