"""The agent's only route to a tool: the Aegis gateway.

There is deliberately no client here for the MCP server itself. Everything the agent can do
goes through the gateway, which decides whether a call is allowed, whether a human must
approve it, and what the tool's output is allowed to say.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Literal

from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

ToolStatus = Literal[
    "completed", "approval_required", "rejected", "timeout", "blocked", "denied", "failed"
]

_ERROR_STATUS: dict[str, ToolStatus] = {
    "APPROVAL_REQUIRED": "approval_required",
    "APPROVAL_REJECTED": "rejected",
    "APPROVAL_TIMEOUT": "timeout",
    "OUTPUT_SECURITY_BLOCKED": "blocked",
    "UNAUTHORIZED_CALLER": "denied",
    "TOOL_NOT_ALLOWED": "denied",
    "TOOL_DENIED": "denied",
    "INVALID_ARGUMENTS": "failed",
}


@dataclass(frozen=True)
class ToolOutcome:
    status: ToolStatus
    #: What the gateway returned as text: fenced untrusted data, or the refusal.
    content: str = ""
    request_id: str | None = None
    result: dict[str, Any] | None = None
    #: Aegis provenance: the output's source, trust level and screening verdict.
    provenance: dict[str, Any] | None = None


class AegisClient:
    def __init__(self, url: str, agent_id: str, role: str) -> None:
        self._url = url
        self._headers = {"x-aegis-agent-id": agent_id, "x-aegis-role": role}

    def list_tools(self) -> list[dict[str, Any]]:
        """The tools this caller may request, as the gateway reports them."""
        return asyncio.run(self._list_tools())

    def call_tool(self, tool: str, arguments: dict[str, Any]) -> ToolOutcome:
        return asyncio.run(self._call_tool(tool, arguments))

    async def _list_tools(self) -> list[dict[str, Any]]:
        async with (
            create_mcp_http_client(headers=self._headers) as http_client,
            streamable_http_client(self._url, http_client=http_client) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            listing = await session.list_tools()
        return [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or "",
                    "parameters": tool.input_schema,
                },
            }
            for tool in listing.tools
        ]

    async def _call_tool(self, tool: str, arguments: dict[str, Any]) -> ToolOutcome:
        async with (
            create_mcp_http_client(headers=self._headers) as http_client,
            streamable_http_client(self._url, http_client=http_client) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.call_tool(tool, arguments)

        meta = result.meta or {}
        text = "\n".join(
            block.text for block in result.content if getattr(block, "type", "") == "text"
        )
        code = meta.get("aegis/error_code")
        return ToolOutcome(
            status=_ERROR_STATUS.get(str(code), "failed") if code else "completed",
            content=text,
            request_id=meta.get("aegis/request_id"),
            result=None if code else result.structured_content,
            provenance=meta.get("aegis/provenance"),
        )
