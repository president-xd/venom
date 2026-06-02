"""
The Agent wrapper. Each agent is a (role, model, provider) bound to the shared
LLMRouter. It forces its own model/provider on every call and prepends the
CIPHER master prompt + its role addendum to the system prompt.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..llm import LLMRouter, Provider, TaskType, complete_json
from ..llm.budget import trim
from ..prompts import agent_system_prompt
from .roles import AgentRole, AgentSpec

logger = logging.getLogger("venom.agents")


@dataclass
class Agent:
    spec: AgentSpec
    router: LLMRouter

    @property
    def role(self) -> AgentRole:
        return self.spec.role

    @property
    def model(self) -> str:
        return self.spec.model()

    @property
    def provider(self) -> Provider:
        return self.spec.provider

    def _system(self, extra: str = "") -> str:
        parts = [agent_system_prompt(), self.spec.system_addendum]
        if extra:
            parts.append(extra)
        return "\n\n---\n\n".join(p for p in parts if p)

    async def complete_text(self, user: str, *, extra_system: str = "",
                            task: TaskType | None = None, **kwargs) -> str:
        result = await self.router.complete(
            task or self.spec.primary_task,
            [{"role": "user", "content": trim(user)}],     # free-tier safe
            system=self._system(extra_system),
            override_provider=self.provider,
            model=self.model,
            temperature=kwargs.pop("temperature", self.spec.temperature),
            **kwargs,
        )
        return result["content"]

    async def complete_json(self, user: str, *, schema_hint: str = "",
                            extra_system: str = "", task: TaskType | None = None,
                            **kwargs) -> dict[str, Any]:
        result = await complete_json(
            self.router,
            task or self.spec.primary_task,
            [{"role": "user", "content": trim(user)}],     # free-tier safe
            system=self._system(extra_system),
            schema_hint=schema_hint,
            override_provider=self.provider,
            model=self.model,
            temperature=kwargs.pop("temperature", self.spec.temperature),
            **kwargs,
        )
        return result["parsed"]
