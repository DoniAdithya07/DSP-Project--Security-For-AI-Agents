from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class ExecuteRequest(BaseModel):
    session_id: Optional[str] = Field(default=None, min_length=8, max_length=128)
    prompt: str = Field(..., min_length=1, max_length=4000)
    role: Literal["researcher", "support", "admin"] = "researcher"
    requested_tool: Optional[str] = Field(default=None, max_length=40)
    tool_args: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("prompt")
    @classmethod
    def normalize_prompt(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("prompt cannot be empty")
        return trimmed

    @field_validator("requested_tool")
    @classmethod
    def normalize_tool(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().lower()
        return normalized or None

    @field_validator("session_id")
    @classmethod
    def normalize_session_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None
