import json

import pytest

from evaluation import instrumentation


@pytest.fixture(autouse=True)
def _reset():
    instrumentation.reset()
    yield
    instrumentation.reset()


def test_emit_without_configure_is_a_noop(tmp_path):
    # não deve levantar nem criar arquivo nenhum
    instrumentation.emit("whatever", foo="bar")


def test_configure_and_emit_writes_json_line(tmp_path):
    path = tmp_path / "events.jsonl"
    instrumentation.configure(path, run_id="run-1")
    instrumentation.emit("decision", slice="URLLC", risk_score=1.23)

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["run_id"] == "run-1"
    assert record["event"] == "decision"
    assert record["slice"] == "URLLC"
    assert record["risk_score"] == 1.23
    assert "ts" in record


def test_timed_emits_start_and_end_with_duration(tmp_path):
    path = tmp_path / "events.jsonl"
    instrumentation.configure(path, run_id="run-2")

    with instrumentation.timed("keygen", slice="EMBB"):
        pass

    lines = [json.loads(line) for line in path.read_text().strip().splitlines()]
    assert [r["event"] for r in lines] == ["keygen_start", "keygen_end"]
    assert lines[1]["duration_seconds"] >= 0
    assert lines[0]["slice"] == "EMBB"


def test_reset_goes_back_to_noop(tmp_path):
    path = tmp_path / "events.jsonl"
    instrumentation.configure(path, run_id="run-3")
    instrumentation.reset()
    instrumentation.emit("after_reset")
    # o arquivo pode ter sido criado (configure já cria o diretório/arquivo
    # vazio), mas não deve ter essa linha
    if path.exists():
        assert "after_reset" not in path.read_text()
