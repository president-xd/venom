"""
Business model graph - the agent's mental model of how the application is
*supposed* to work. Four node types (Entity, Transition, Rule, Actor) plus
explicit economic flows.

The graph is the substrate for hypothesis generation: invalid transition paths,
faith-based (unenforced) rules, and asymmetric economic flows are all read off it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from itertools import product


@dataclass
class Entity:
    name: str
    states: list[str] = field(default_factory=list)
    ownership_model: str = ""          # who owns instances
    access_model: dict[str, list[str]] = field(default_factory=dict)  # role -> [read/write/delete]


@dataclass
class Transition:
    entity: str
    from_state: str
    to_state: str
    trigger: str = ""                  # API endpoint key, e.g. "POST /api/v1/orders/{id}/ship"
    preconditions: list[str] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)
    idempotent: bool = False
    reversible: bool = False


@dataclass
class Rule:
    rule_id: str
    rule_type: str                     # RATE_LIMIT | UNIQUENESS | TEMPORAL | RELATIONAL | THRESHOLD | SEQUENCE
    description: str
    attached_to: str = ""              # entity or transition trigger
    enforced: bool | None = None       # None = unknown; False = "faith-based" (no visible enforcement)


@dataclass
class Actor:
    role: str
    can_create: list[str] = field(default_factory=list)
    can_read: list[str] = field(default_factory=list)
    can_update: list[str] = field(default_factory=list)
    can_delete: list[str] = field(default_factory=list)
    can_impersonate: bool = False


@dataclass
class EconomicFlow:
    from_asset: str
    to_asset: str
    rate: str = ""
    reverse_flow: str = ""
    abuse_note: str = ""


class BusinessModelGraph:
    def __init__(self) -> None:
        self.entities: dict[str, Entity] = {}
        self.transitions: list[Transition] = []
        self.rules: list[Rule] = []
        self.actors: dict[str, Actor] = {}
        self.economic_flows: list[EconomicFlow] = []

    # ------------------------------------------------------------- builders
    def add_entity(self, entity: Entity) -> None:
        self.entities[entity.name] = entity

    def add_transition(self, t: Transition) -> None:
        self.transitions.append(t)

    def add_rule(self, r: Rule) -> None:
        self.rules.append(r)

    def add_actor(self, a: Actor) -> None:
        self.actors[a.role] = a

    def add_economic_flow(self, f: EconomicFlow) -> None:
        self.economic_flows.append(f)

    # ------------------------------------------------------------- analysis
    def valid_transitions(self, entity: str) -> set[tuple[str, str]]:
        return {(t.from_state, t.to_state) for t in self.transitions if t.entity == entity}

    def invalid_transition_paths(self, entity: str) -> list[tuple[str, str]]:
        """Every (from, to) pair among the entity's states that is NOT a declared
        valid transition - these are the sequence-violation test candidates."""
        ent = self.entities.get(entity)
        if not ent or len(ent.states) < 2:
            return []
        valid = self.valid_transitions(entity)
        return [
            (a, b)
            for a, b in product(ent.states, ent.states)
            if a != b and (a, b) not in valid
        ]

    def faith_based_rules(self) -> list[Rule]:
        """Rules documented but with no visible enforcement - primary targets."""
        return [r for r in self.rules if r.enforced is False]

    def asymmetric_flows(self) -> list[EconomicFlow]:
        """Economic flows that are reversible (round-trip / arbitrage candidates)."""
        return [f for f in self.economic_flows if f.reverse_flow]

    def trigger_for(self, entity: str, from_state: str, to_state: str) -> str | None:
        for t in self.transitions:
            if t.entity == entity and t.from_state == from_state and t.to_state == to_state:
                return t.trigger
        return None

    # ------------------------------------------------------------- serialize
    def to_dict(self) -> dict:
        return {
            "entities": {k: asdict(v) for k, v in self.entities.items()},
            "transitions": [asdict(t) for t in self.transitions],
            "rules": [asdict(r) for r in self.rules],
            "actors": {k: asdict(v) for k, v in self.actors.items()},
            "economic_flows": [asdict(f) for f in self.economic_flows],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BusinessModelGraph":
        g = cls()
        for v in data.get("entities", {}).values():
            g.add_entity(Entity(**v))
        for t in data.get("transitions", []):
            g.add_transition(Transition(**t))
        for r in data.get("rules", []):
            g.add_rule(Rule(**r))
        for a in data.get("actors", {}).values():
            g.add_actor(Actor(**a))
        for f in data.get("economic_flows", []):
            g.add_economic_flow(EconomicFlow(**f))
        return g
