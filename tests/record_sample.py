"""Create a two-event journal in a separate recorder process for integration tests."""

import json
import sys

from agent_blackbox import AgentBlackbox


def record_sample(storage):
    box = AgentBlackbox(storage)

    @box.trace("planner")
    def plan():
        raise ValueError("sample input was incomplete")

    try:
        plan()
    except ValueError:
        pass
    parent = next(reversed(box.events))

    @box.trace("worker", parent_event_hash=parent)
    def finish():
        return "recovered"

    finish()
    return {"parent": parent, "child": next(reversed(box.events))}


if __name__ == "__main__":
    print(json.dumps(record_sample(sys.argv[1])))
