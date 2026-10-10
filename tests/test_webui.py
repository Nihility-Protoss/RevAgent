"""Web UI 审查面板（webui/server.py）的接口测试。

用 FastAPI TestClient 在进程内驱动应用（不占真实端口）；LLM 全部复用
tests.test_integration 的 ScriptedFakeChatModel 脚本化假模型注入，不消耗真实 API。
黑板与 checkpoints.db 落在 tmp_path 下（fixture 已 chdir），不污染仓库。
"""
import os
import shutil
import time

import pytest
from fastapi.testclient import TestClient

import webui.server as server
from tests.test_integration import ScriptedFakeChatModel, _make_export_dir
from webui.server import app

INPUT_DIR_NAME = "webui_case"  # data/input/webui_case_export_for_ai


@pytest.fixture
def webui_env(tmp_path, monkeypatch):
    """隔离的 Web UI 运行环境：临时 cwd + 最小 IDA 导出 fixture + 假模型注入。"""
    monkeypatch.chdir(tmp_path)
    staging = _make_export_dir(str(tmp_path / "staging"))  # 产出 staging/export
    os.makedirs(os.path.join("data", "input"), exist_ok=True)
    shutil.move(staging, os.path.join("data", "input", INPUT_DIR_NAME + "_export_for_ai"))
    server.set_llm(ScriptedFakeChatModel())
    server.RUNS.clear()
    yield tmp_path
    server.set_llm(None)
    server.RUNS.clear()


def _wait_for_status(client: TestClient, project: str, want: str, timeout: float = 90) -> dict:
    """轮询 status 直到目标状态；failed 时直接失败并带出错误信息。"""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        resp = client.get(f"/api/analysis/{project}/status")
        assert resp.status_code == 200
        last = resp.json()
        if last["status"] == want:
            return last
        if last["status"] == "failed":
            pytest.fail(f"分析运行失败: {last.get('error')}")
        time.sleep(0.3)
    pytest.fail(f"等待状态 {want!r} 超时（{timeout}s），最后状态: {last}")


def _start(client: TestClient, project: str) -> dict:
    resp = client.post("/api/analysis/start", json={
        "project_name": project, "input_name": INPUT_DIR_NAME,
    })
    assert resp.status_code == 202, resp.text
    return resp.json()


# === 启动与状态查询 ===

def test_start_reaches_approval_gate_and_review_payload(webui_env):
    """启动分析后图推进到审批门挂起；review 返回 interrupt 负载与候选函数列表。"""
    project = "webui_case"
    with TestClient(app) as client:
        assert _start(client, project)["status"] == "running"

        st = _wait_for_status(client, project, "awaiting_approval")
        assert st["status"] == "awaiting_approval"
        # checkpoints.db 已落盘（thread_id = 项目名）
        assert os.path.exists(os.path.join("data", "output", project, "checkpoints.db"))

        resp = client.get(f"/api/analysis/{project}/review")
        assert resp.status_code == 200
        data = resp.json()
        assert data["kind"] == "phase2_approval"
        assert "行为定型" in data["message"]
        assert data["error"] is None

        review = data["review"]
        # 假模型的行为定型结论（Stealer/high）与高风险指标计数
        assert review["behavior_profile"]["behavior_profile"]["primary_type"] == "Stealer"
        assert review["high_risk_strings"] == 1
        assert review["high_risk_apis"] == 1
        addrs = [c["func_addr"] for c in review["candidates"]]
        assert "0x401000" in addrs
        assert review["total_functions"] == 10

        # 未提交决定前 report 尚未生成
        resp = client.get(f"/api/analysis/{project}/report")
        assert resp.status_code == 404


def test_duplicate_start_rejected(webui_env):
    """同项目重复启动：运行中与等待审批两种状态下都返回 409。"""
    project = "webui_dup"
    with TestClient(app) as client:
        _start(client, project)
        _wait_for_status(client, project, "awaiting_approval")
        resp = client.post("/api/analysis/start", json={
            "project_name": project, "input_name": INPUT_DIR_NAME,
        })
        assert resp.status_code == 409


def test_start_with_unknown_input_name_rejected(webui_env):
    """input_name 无法解析时返回 400 与候选信息。"""
    with TestClient(app) as client:
        resp = client.post("/api/analysis/start", json={
            "project_name": "webui_bad", "input_name": "no_such_dir",
        })
        assert resp.status_code == 400
        assert "未匹配" in resp.json()["detail"]


def test_status_of_unknown_project_is_not_found(webui_env):
    """服务重启后对陌生项目查询状态不报错，返回 not_found。"""
    with TestClient(app) as client:
        resp = client.get("/api/analysis/ghost_project/status")
        assert resp.status_code == 200
        assert resp.json()["status"] == "not_found"


def test_project_name_path_traversal_rejected(webui_env):
    """项目名带路径穿越字符时一律 400。"""
    with TestClient(app) as client:
        resp = client.post("/api/analysis/start", json={"project_name": "../evil"})
        assert resp.status_code == 400
        # 含 ".." 子串的项目名（URL 单段内）被 handler 校验拒绝
        resp = client.get("/api/analysis/..evil/status")
        assert resp.status_code == 400


# === 审批决定（CONFIRM / MODIFY） ===

def test_decision_confirm_runs_to_completion(webui_env):
    """审批门提交 CONFIRM 后图跑完：状态 completed，final_report.md 可读。"""
    project = "webui_confirm"
    with TestClient(app) as client:
        _start(client, project)
        _wait_for_status(client, project, "awaiting_approval")

        resp = client.post(f"/api/analysis/{project}/decision", json={"decision": "CONFIRM"})
        assert resp.status_code == 200
        assert resp.json()["resumed"] == "CONFIRM"

        st = _wait_for_status(client, project, "completed")
        assert st["phase2_human_decision"] == "CONFIRM"
        assert st["report_md_path"].endswith("final_report.md")

        resp = client.get(f"/api/analysis/{project}/report")
        assert resp.status_code == 200
        assert "综合参考手册" in resp.json()["markdown"]


def test_decision_modify_runs_to_completion(webui_env):
    """MODIFY 附带函数地址列表，转为 Command(resume='MODIFY addr,...') 恢复图。"""
    project = "webui_modify"
    with TestClient(app) as client:
        _start(client, project)
        _wait_for_status(client, project, "awaiting_approval")

        resp = client.post(f"/api/analysis/{project}/decision", json={
            "decision": "MODIFY", "functions": ["0x401000", "0x409999"],
        })
        assert resp.status_code == 200
        assert resp.json()["resumed"] == "MODIFY 0x401000,0x409999"

        st = _wait_for_status(client, project, "completed")
        # 审批门原文写入 state（与 CLI 的 MODIFY 路径语义一致）
        assert st["phase2_human_decision"] == "MODIFY 0x401000,0x409999"

        resp = client.get(f"/api/analysis/{project}/report")
        assert resp.status_code == 200


def test_decision_validation_errors(webui_env):
    """MODIFY 缺 functions / 空 decision / 非审批门状态，分别 400/400/409；
    CONFIRM/MODIFY 之外的任意字符串原样透传（B1 起不再 400）。"""
    project = "webui_invalid"
    with TestClient(app) as client:
        # 未启动的项目不在审批门
        resp = client.post(f"/api/analysis/{project}/decision", json={"decision": "CONFIRM"})
        assert resp.status_code == 409

        _start(client, project)
        _wait_for_status(client, project, "awaiting_approval")
        resp = client.post(f"/api/analysis/{project}/decision", json={"decision": "  "})
        assert resp.status_code == 400
        resp = client.post(f"/api/analysis/{project}/decision", json={"decision": "MODIFY"})
        assert resp.status_code == 400

        # 合法提交后图继续跑完，证明前面的 400 校验没有破坏审批现场
        resp = client.post(f"/api/analysis/{project}/decision", json={"decision": "CONFIRM"})
        assert resp.status_code == 200
        _wait_for_status(client, project, "completed")


def test_decision_passthrough_arbitrary_text(webui_env):
    """任意字符串 decision（如 token 预算闸门的 CONTINUE）原样透传为 resume 文本。

    透传给审批门的无法识别回复会计入无效尝试并重新挂起（不破坏审批现场），
    之后提交 CONFIRM 照常跑完。
    """
    project = "webui_passthrough"
    with TestClient(app) as client:
        _start(client, project)
        _wait_for_status(client, project, "awaiting_approval")

        resp = client.post(f"/api/analysis/{project}/decision", json={"decision": "CONTINUE"})
        assert resp.status_code == 200
        assert resp.json()["resumed"] == "CONTINUE"  # 原样透传，未改写未拒绝

        # 审批门不识别 CONTINUE：记为无效回复并重新挂起（3 次上限内）
        _wait_for_status(client, project, "awaiting_approval")

        resp = client.post(f"/api/analysis/{project}/decision", json={"decision": "CONFIRM"})
        assert resp.status_code == 200
        st = _wait_for_status(client, project, "completed")
        assert st["phase2_human_decision"] == "CONFIRM"


def test_review_rejected_when_not_awaiting(webui_env):
    """不在审批门时 review 返回 409。"""
    with TestClient(app) as client:
        resp = client.get("/api/analysis/ghost_project/review")
        assert resp.status_code == 409


# === USER.md 异步沟通通道（与图运行解耦，纯落盘） ===

def test_usermd_get_auto_creates_skeleton(webui_env):
    """GET usermd：项目未跑过分析也可读——自动建骨架，返回原文与空问题列表。"""
    with TestClient(app) as client:
        resp = client.get("/api/analysis/usermd_case/usermd")
        assert resp.status_code == 200
        data = resp.json()
        assert "## Agent 的疑惑与待确认问题" in data["content"]
        assert "## 用户着重关心的内容" in data["content"]
        assert data["questions"] == []
        assert data["focus"] == ""
        # 骨架真实落盘到 docs/{project}/USER.md
        assert os.path.exists(os.path.join("data", "output", "docs", "usermd_case", "USER.md"))


def test_usermd_reply_appends_answer(webui_env):
    """POST reply：回答写入对应编号问题的"用户回答："代码块，GET 可读回。"""
    project = "usermd_reply_case"
    # 模拟 orchestrator 写入的待确认问题（Agent 侧写入路径）
    from tools.docs_tools import user_md_append_question
    user_md_append_question(project, "矛盾确认：0x401000 功能判定冲突", "两主题结论不一致。")

    with TestClient(app) as client:
        resp = client.post(f"/api/analysis/{project}/usermd/reply", json={
            "question_no": 1, "answer": "以网络主题的结论为准。",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

        resp = client.get(f"/api/analysis/{project}/usermd")
        data = resp.json()
        assert len(data["questions"]) == 1
        assert data["questions"][0]["answered"] is True
        assert data["questions"][0]["answer"] == "以网络主题的结论为准。"
        assert "用户回答：" in data["content"]


def test_usermd_reply_validation(webui_env):
    """reply 校验：空回答 400；编号不存在 404；非法项目名 400。"""
    from tools.docs_tools import user_md_append_question
    user_md_append_question("usermd_bad", "标题", "正文")
    with TestClient(app) as client:
        resp = client.post("/api/analysis/usermd_bad/usermd/reply", json={
            "question_no": 1, "answer": "  ",
        })
        assert resp.status_code == 400
        resp = client.post("/api/analysis/usermd_bad/usermd/reply", json={
            "question_no": 99, "answer": "回答",
        })
        assert resp.status_code == 404
        resp = client.post("/api/analysis/..evil/usermd/reply", json={
            "question_no": 1, "answer": "回答",
        })
        assert resp.status_code == 400
