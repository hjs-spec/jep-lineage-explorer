from jep_lineage.engine import LineageEngine
from jep_lineage.model import ReplayEvent
from jep_lineage.cli import render_text


def report(rows):
    engine = LineageEngine(ReplayEvent.from_json(i + 1, row) for i, row in enumerate(rows))
    result = engine.build_report()
    assert engine.build_report().to_dict() == result.to_dict()
    return result


def grant(id, parent=None, **kw):
    return dict(type="delegate", timestamp=1 if parent is None else 2, delegation_id=id,
                parent_id=parent, from_agent="owner" if parent is None else "planner",
                to_agent="planner" if parent is None else "worker", scopes=["read"], **kw)


def test_use_requires_delegatee_and_live_ancestors():
    rows = [grant("root"), grant("child", "root"),
            dict(type="revoke", timestamp=3, delegation_id="root"),
            dict(type="authority_used", timestamp=4, delegation_id="child", actor="attacker", scopes=["read"])]
    codes = {issue.code for issue in report(rows).issues}
    assert {"authority-actor-mismatch", "inactive-ancestor-use"} <= codes


def test_replay_ids_do_not_share_grants():
    result = report([grant("root", replay_id="one"), grant("root", replay_id="two"),
                     dict(type="authority_used", timestamp=3, replay_id="three", delegation_id="root", actor="planner")])
    assert len(result.delegations) == 2
    assert "unknown-delegation-use" in {i.code for i in result.issues}
    assert "duplicate-delegation" not in {i.code for i in result.issues}


def test_cycles_are_reported_and_render_without_recursing_forever():
    result = report([grant("a", "b"), grant("b", "a")])
    assert "delegation-cycle" in {i.code for i in result.issues}
    assert result.to_dict()["delegation_tree"]
    assert "cycle" in render_text(result)
