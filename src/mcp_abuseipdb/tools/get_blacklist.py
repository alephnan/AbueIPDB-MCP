"""Tool for retrieving AbuseIPDB blacklist."""

import logging
from typing import Any, Dict, Optional

from mcp.types import Tool, TextContent, CallToolResult

from ..settings import Settings
from ..cache import CacheManager, RateLimiter
from ..client_abuseipdb import AbuseIPDBClient
from ..models import BlacklistResponse, APIError

logger = logging.getLogger(__name__)


class GetBlacklistTool:
    """Tool for retrieving AbuseIPDB blacklist."""

    def __init__(self, settings: Settings, cache: CacheManager, rate_limiter: RateLimiter):
        self.settings = settings
        self.cache = cache
        self.rate_limiter = rate_limiter

    async def get_tool_definition(self) -> Tool:
        """Get the tool definition for MCP."""
        return Tool(
            name="get_blacklist",
            description="Retrieve the AbuseIPDB blacklist of malicious IP addresses",
            inputSchema={
                "type": "object",
                "properties": {
                    "confidence_minimum": {
                        "type": "integer",
                        "description": "Minimum confidence level (0-100)",
                        "default": 90,
                        "minimum": 0,
                        "maximum": 100,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of entries to retrieve",
                        "minimum": 1,
                        "maximum": 10000,
                    },
                },
                "required": [],
            },
        )

    async def execute(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Execute the get_blacklist tool."""
        try:
            # Extract and validate arguments
            confidence_minimum = arguments.get(
                "confidence_minimum",
                self.settings.blacklist_confidence_min
            )
            limit = arguments.get("limit")

            # Validate confidence_minimum
            if not 0 <= confidence_minimum <= 100:
                raise ValueError("confidence_minimum must be between 0 and 100")

            # Validate limit
            if limit is not None and not 1 <= limit <= 10000:
                raise ValueError("limit must be between 1 and 10000")

            # Create cache key
            cache_params = {"confidence": confidence_minimum}
            if limit is not None:
                cache_params["limit"] = limit

            cache_key = self.cache.create_cache_key("blacklist", cache_params)

            # Try cache first (blacklist changes infrequently, longer TTL)
            cached_result = await self.cache.get(cache_key)
            if cached_result:
                logger.info(f"Cache hit for blacklist (confidence={confidence_minimum})")
                blacklist_response = BlacklistResponse.model_validate(cached_result)
            else:
                # Check rate limit
                if not await self.rate_limiter.acquire():
                    return CallToolResult(
                        content=[
                            TextContent(
                                type="text",
                                text="Rate limit exceeded. Please try again later."
                            )
                        ],
                        isError=True,
                    )

                # Make API call
                async with AbuseIPDBClient(self.settings) as client:
                    try:
                        blacklist_response = await client.get_blacklist(
                            confidence_minimum=confidence_minimum,
                            limit=limit,
                        )

                        # Cache the result with longer TTL (blacklist changes less frequently)
                        await self.cache.set(
                            cache_key,
                            blacklist_response.model_dump(),
                            ttl=7200  # 2 hours
                        )
                        logger.info(f"Cached blacklist result (confidence={confidence_minimum})")

                    except APIError as e:
                        logger.error(f"API error retrieving blacklist: {e.error}")
                        return CallToolResult(
                            content=[
                                TextContent(
                                    type="text",
                                    text=f"API Error: {e.error}"
                                )
                            ],
                            isError=True,
                        )

            # Analyze blacklist data
            entries = blacklist_response.data
            total_entries = len(entries)

            # Group by country
            country_stats = {}
            confidence_stats = {"90-100": 0, "75-89": 0, "50-74": 0, "0-49": 0}

            for entry in entries:
                # Country stats
                country = entry.country_code or "Unknown"
                country_stats[country] = country_stats.get(country, 0) + 1

                # Confidence stats
                confidence = entry.abuse_confidence_percentage
                if confidence >= 90:
                    confidence_stats["90-100"] += 1
                elif confidence >= 75:
                    confidence_stats["75-89"] += 1
                elif confidence >= 50:
                    confidence_stats["50-74"] += 1
                else:
                    confidence_stats["0-49"] += 1

            # Get top countries
            top_countries = sorted(
                country_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]

            # Format response
            result = {
                "generated_at": blacklist_response.generated_at.isoformat(),
                "total_entries": total_entries,
                "confidence_minimum_used": confidence_minimum,
                "limit_used": limit,
                "confidence_distribution": confidence_stats,
                "top_countries": dict(top_countries),
                "sample_entries": [
                    {
                        "ip_address": entry.ip_address,
                        "country_code": entry.country_code,
                        "abuse_confidence": entry.abuse_confidence_percentage,
                        "last_reported": entry.last_reported_at.isoformat() if entry.last_reported_at else None,
                    }
                    for entry in entries[:20]  # First 20 entries
                ],
            }

            # Create summary text
            summary_lines = [
                f"Blacklist Retrieved: {total_entries:,} entries",
                f"Generated: {blacklist_response.generated_at}",
                f"Minimum Confidence: {confidence_minimum}%",
            ]

            if limit:
                summary_lines.append(f"Limit Applied: {limit:,}")

            summary_lines.extend([
                "\nConfidence Distribution:",
                f"  • 90-100%: {confidence_stats['90-100']:,}",
                f"  • 75-89%:  {confidence_stats['75-89']:,}",
                f"  • 50-74%:  {confidence_stats['50-74']:,}",
                f"  • 0-49%:   {confidence_stats['0-49']:,}",
            ])

            if top_countries:
                summary_lines.append("\nTop Countries:")
                for country, count in top_countries[:5]:
                    summary_lines.append(f"  • {country}: {count:,}")

            summary = "\n".join(summary_lines)

            # Add sample entries
            if entries:
                summary += "\n\nSample Entries:"
                for entry in entries[:10]:
                    last_reported = entry.last_reported_at.strftime("%Y-%m-%d") if entry.last_reported_at else "Unknown"
                    summary += f"\n  • {entry.ip_address} ({entry.country_code or 'Unknown'}) - {entry.abuse_confidence_percentage}% - Last: {last_reported}"

            return CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=f"{summary}\n\nDetailed data:\n{result}"
                    )
                ]
            )

        except ValueError as e:
            logger.error(f"Validation error in get_blacklist: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Validation Error: {e}")],
                isError=True,
            )
        except Exception as e:
            logger.error(f"Unexpected error in get_blacklist: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unexpected Error: {e}")],
                isError=True,
            )