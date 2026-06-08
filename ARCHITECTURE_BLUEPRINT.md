# Malware Analysis ADK Agent -- Architecture Blueprint v3.0

> **Version**: 3.0 (Architecture Blueprint)  
> **ADK Version**: 2.1.0+  
> **Core Paradigm**: Hybrid Orchestration -- Static Graph + Dynamic Workflow + Shared Blackboard  
> **Design Principle**: Drawing on Cairn's public blackboard architecture of "shared state space + decentralized scheduling", with ADK Dynamic Workflow handling post-Scheduler dynamic phases, and human intervention available at any breakpoint

---

## 1. Overall Architecture

### 1.1 Architecture Evolution Path

```
+-----------------------------------------------------------------------------+
|                        v2.0 MVP (Current)                                   |
|  Static Graph Workflow only                                                 |
|  Phase 0 (fan-out) -> Phase 1 (fan-out) -> Phase 2 (Scheduler + HITL)       |
|  Centralized scheduling, session-state based                                |
+-----------------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------------+
|                        v3.0 Target Architecture                             |
|                                                                             |
|   +--------------+     +--------------+     +--------------------------+   |
|   |  Phase 0/1   |---->|  Phase 2     |---->|  Phase 3+ Dynamic        |   |
|   | Static Graph |     | Blackboard   |     |  Workflow (Runtime)      |   |
|   | (Deterministic)    | + Scheduler  |     |  (Programmatic)          |   |
|   +--------------+     +--------------+     +--------------------------+   |
|          |                    |                        |                    |
|          +--------------------+------------------------+                    |
|                         Shared Blackboard State                             |
|                    (ADK Session State + Event System)                       |
|                                                                             |
|   <----------------- Human Intervention Points (HITL) ------------------->   |
|                                                                             |
+-----------------------------------------------------------------------------+
```

### 1.2 Core Design Decisions

| Dimension | v2.0 Status | v3.0 Blueprint | Source |
|-----------|-------------|----------------|--------|
| **Orchestration Engine** | Pure Static Graph (`Workflow` + edges tuples) | **Hybrid**: Static Graph (Phase 0/1) + Dynamic Workflow (Phase 2+) | ADK 2.0 Graph + Dynamic Workflows [^2^] |
| **Scheduling Model** | Centralized (Scheduler decides everything) | **Decentralized** (Workers read blackboard and autonomously decide; Scheduler maintains blackboard + triggers HITL) | Cairn Dispatcher Design [^8^] |
| **State Management** | Flat session state (key-value) | **Shared Blackboard State Space** (append-only facts, structured context, versioned snapshots) | Cairn Server Protocol [^7^] |
| **Human Intervention** | Single HITL after Phase 2 | **Intervention at any breakpoint** (strategic / tactical / review levels; pause/modify/inject instructions) | ADK RequestInput [^25^] |
| **Dynamic Capability** | None (fixed number of Workers) | **Runtime dynamic construction** (dynamically create analysis nodes based on human confirmation, loop verification, conditional branching) | ADK Dynamic Workflows [^28^] |
| **Worker Communication** | Through Scheduler relay | **Blackboard indirect coordination** (stigmergy pheromone mechanism; Workers read/write blackboard, no direct communication) | Cairn Blackboard Architecture [^7^] |

### 1.3 Why a Hybrid Architecture

**Static Graph remains for Phase 0/1 because**:

Phase 0 (Triage Swarm) and Phase 1 (Deep Swarm) have **compile-time deterministic** analysis dimensions. The five Workers (String Analyst, API Profiler, Export Analyzer, Behavior Synthesizer, Function Boundary Detector) have clearly defined responsibility boundaries and fixed fan-out/fan-in dependency relationships. Using `Workflow` edges tuple definitions provides **compile-time validation** and **deterministic execution guarantees** [^2^]. ADK Graph's `JoinNode` mechanism naturally supports Phase 0's three Workers completing before triggering Phase 1, and Phase 1's two Workers completing before triggering the Scheduler [^2^].

**Dynamic Workflow connects after Phase 2 because**:

Post-Phase 2 workflows are **runtime-determined**. The number N of human-confirmed functions determines how many Function Deep Analyzer instances to create; verification loop termination conditions ("high confidence findings verified" or "maximum iterations reached") can only be determined during execution; conditional loading of LNK samples, multi-sample correlation analysis, and other extension paths all depend on runtime state [^28^]. ADK Dynamic Workflow's `@node` + `ctx.run_node()` pattern allows programmatic node construction in code, implementing loops and recursion, precisely filling the gaps of Static Graph in dynamic scenarios.

**Blackboard mode runs through the entire workflow because**:

Cairn's core insight is that when multiple expert Workers work around a shared blackboard, no central scheduler needs to assign tasks. Each Worker reads the current blackboard state, autonomously judges what it can contribute, writes back after producing, and other Workers continue based on that [^7^]. This **stigmergy (pheromone) coordination mechanism** eliminates single-point bottlenecks, naturally supports horizontal scaling, and each Worker's OODA loop (Observe-Orient-Decide-Act) runs independently, with decision speed not limited by the central node [^8^].

---

## 2. Shared Blackboard State Space Design

### 2.1 Design Origin and Adaptation

Cairn's public blackboard protocol models the exploration process as a **directed acyclic graph** (Fact -> Intent -> Fact), with core concepts including:

- **Fact**: Append-only objective facts; state changes expressed by adding new Facts [^7^]
- **Intent**: Worker-declared exploration intentions ("what I will do"), not assigned tasks [^7^]
- **Hint**: Strategy annotations providing direction for subsequent Workers [^7^]
- **Decentralized**: No central scheduling; multiple consumers read the graph concurrently, declare their own intentions, and produce facts [^8^]

This architecture **draws on core ideas** but **does not do a complete protocol port**: it uses ADK's native `session.state` as the blackboard carrier, introducing **Fact-style state appending** and **Worker autonomous decision-making** mechanisms, while retaining ADK's `Event` system and `Workflow` orchestration as infrastructure.

### 2.2 Blackboard State Model

The blackboard state adopts a **layered namespace** design. All Worker outputs are written following the "append-only" principle, with complete historical versions retained:

```
session.state["blackboard"] -------------------------------------------------+
|                                                                              |
|  +-- facts/              <- Objective fact layer (append-only)               |
|  |   +-- origin.json          # Sample original info (PE header, filename, hash) |
|  |   +-- f_001_string_analysis.json     # Phase 0 String Analyst output      |
|  |   +-- f_002_api_behavior.json        # Phase 0 API Profiler output        |
|  |   +-- f_003_export_analysis.json     # Phase 0 Export Analyzer output     |
|  |   +-- f_004_behavior_profile.json    # Phase 1 Behavior Synthesizer       |
|  |   +-- f_005_function_boundary.json   # Phase 1 Function Boundary         |
|  |   +-- f_006_scheduler_decision.json  # Phase 2 Scheduler decision        |
|  |   +-- f_007_human_approval.json      # HITL human confirmation result    |
|  |   +-- f_008_func_deep_001.json       # Phase 3 function deep analysis #1 |
|  |   +-- f_009_func_deep_002.json       # Phase 3 function deep analysis #2 |
|  |   +-- f_010_verification_result.json # Phase 4 verification result       |
|  |   +-- ...                            # Dynamically appended new facts     |
|  |                                                                           |
|  +-- intents/            <- Exploration intention layer (Worker-declared)    |
|  |   +-- i_001_analyze_func_0x401000.json  # "analyze function 0x401000"    |
|  |   +-- i_002_verify_behavior_x.json      # "verify behavior inference X"  |
|  |   +-- i_003_compare_sample_family.json  # "compare sample family traits" |
|  |   +-- ...                              # Dynamically declared intents   |
|  |                                                                           |
|  +-- hints/              <- Strategy annotation layer (human or Worker)      |
|  |   +-- h_001_focus_on_persistence.json   # "focus on persistence mechanisms" |
|  |   +-- h_002_ignore_thunks.json          # "ignore thunk functions"       |
|  |   +-- ...                               # Dynamically appended hints     |
|  |                                                                           |
|  +-- meta/               <- Metadata and coordination layer                  |
|  |   +-- version: int                      # Blackboard version (monotonic) |
|  |   +-- last_updated: str                 # ISO timestamp                  |
|  |   +-- active_worker: str | null         # Worker holding reason lease    |
|  |   +-- execution_phase: str              # Current execution phase        |
|  |   +-- pending_hitl: dict | null         # Context pending human review   |
|  |   +-- checkpoints: list                 # State snapshots (for rollback) |
|  |                                                                           |
|  +-- index/              <- Fast index layer                                 |
|      +-- facts_by_worker: dict       # Worker -> fact_ids mapping           |
|      +-- facts_by_tag: dict          # tag -> fact_ids mapping              |
|      +-- intents_by_status: dict     # status -> intent_ids mapping         |
|      +-- function_coverage: dict     # Analyzed function addr -> fact_id    |
```

### 2.3 Fact Append-Only Principle

State changes **never overwrite history**; instead, they are expressed by appending new Facts. For example:

```python
# Wrong: overwrite historical state
session.state["blackboard"]["facts"]["behavior_profile"] = new_profile

# Correct: append new Fact, preserve complete history
session.state["blackboard"]["facts"]["f_004_behavior_profile_v2"] = {
    "content": new_profile,
    "supersedes": "f_004_behavior_profile",  # Indicate superseded old Fact
    "reason": "human_modified",               # Update reason
    "timestamp": "2026-06-08T10:30:00Z"
}
```

Direct benefits of this design:

1. **Complete audit log**: Each analysis conclusion's evolution path is traceable for review and debugging
2. **Hallucination detection**: Comparing the same Worker's outputs at different time points can identify inconsistencies
3. **Human rollback**: When human judgment determines an analysis direction was wrong, it can explicitly roll back to a specific Fact version
4. **Worker adaptation**: When Workers read the blackboard and see multiple versions of Facts, they autonomously judge which is latest and which is credible

### 2.4 Comparison with Traditional Session State

| Feature | v2.0 Session State | v3.0 Blackboard State |
|---------|-------------------|----------------------|
| **Data Model** | Flat key-value | Layered namespace (facts/intents/hints/meta/index) |
| **Modification Semantics** | Overwrite (`state[key] = value`) | Append-only (supersedes chain) |
| **Historical Visibility** | None (old values lost) | Complete (all historical Facts retained) |
| **Worker Coordination** | Through Scheduler relay | Blackboard indirect coordination (stigmergy) |
| **Human Intervention** | Single HITL then resume | Pause/modify/inject Hint at any breakpoint |
| **State Rollback** | Not supported | Rollback based on checkpoint snapshots |
| **Debuggability** | Limited (current state only) | Strong (complete state evolution graph) |

---

## 3. Decentralized Scheduling Mechanism

### 3.1 Scheduler Role Restructuring

In v2.0, the Scheduler Agent was a **central router**: reading 5 Worker outputs, integrating summaries, and triggering human review. In v3.0, the Scheduler is demoted to a **blackboard maintainer + situation assessor**, with redefined responsibility boundaries:

```
+-------------------------------------------------------------------------+
|                    v2.0 Centralized Scheduler                             |
|                                                                         |
|   5 Worker Outputs --> [Scheduler] --> Decision --> HITL Callback       |
|                            |                                            |
|                     All decisions centralized here                      |
+-------------------------------------------------------------------------+

+-------------------------------------------------------------------------+
|                   v3.0 Decentralized + Scheduler                          |
|                                                                         |
|   +-------------+    +-------------+    +-------------+                 |
|   |  Worker A   |    |  Worker B   |    |  Worker C   |                 |
|   | (read bb)   |    | (read bb)   |    | (read bb)   |                 |
|   | -> judge    |    | -> judge    |    | -> judge    |                 |
|   | -> produce  |    | -> produce  |    | -> produce  |                 |
|   | -> write    |    | -> write    |    | -> write    |                 |
|   +------+------+    +------+------+    +------+------+                 |
|          |                  |                  |                          |
|          +------------------+------------------+                          |
|                              |                                            |
|                              v                                            |
|                    +-----------------+                                    |
|                    |   Blackboard    |                                    |
|                    | (shared state)  |                                    |
|                    +--------+--------+                                    |
|                             |                                             |
|                    +--------v--------+                                    |
|                    |   Scheduler     |                                    |
|                    | (bb maintainer) |                                    |
|                    | - Situation     |                                    |
|                    |   assessment    |                                    |
|                    | - HITL trigger  |                                    |
|                    | - Lifecycle mgmt|                                    |
|                    | - Checkpoint    |                                    |
|                    +-----------------+                                    |
+-------------------------------------------------------------------------+
```

### 3.2 Worker Autonomous Decision Mode (OODA Loop)

Each Worker's runtime behavior follows the **OODA loop** (Observe-Orient-Decide-Act), isomorphic to the consumer work loop in Cairn [^7^]:

| Stage | Behavior | Blackboard Interaction |
|-------|----------|----------------------|
| **Observe** | Read all facts, intents, hints on the blackboard | `read_blackboard()` -> get complete state snapshot |
| **Orient** | Based on current situation: what can I contribute? Need to declare new intent? | Analyze fact coverage, identify gaps |
| **Decide** | Decide: execute analysis / declare new intent / request human input | If uncertainty found, write hint requesting clarification |
| **Act** | Execute analysis task, produce structured Fact | `write_fact()` -> append new fact, update index |

Workers **do not wait for Scheduler task assignment**. They actively read the blackboard and judge autonomously. The Scheduler only intervenes in these scenarios:

1. **Situation assessment**: Periodically assess blackboard state to determine if HITL needs to be triggered
2. **HITL trigger**: When high-risk findings, confidence conflicts, or human intervention requests are detected, pause the workflow
3. **Lifecycle management**: Decide when to transition from Phase 0/1 Static Graph to Phase 2+ Dynamic Workflow after completion
4. **Checkpoint snapshots**: Save blackboard state at key nodes to support rollback

### 3.3 Differences from Cairn's Scheduling Model

| Dimension | Cairn Original Model | This Architecture Adaptation |
|-----------|---------------------|------------------------------|
| **Protocol Layer** | Complete REST API (Fact/Intent/Hint/Claim/Heartbeat) | ADK native `session.state` + `Event` system |
| **Scheduler** | Dispatcher (independent process, coordinates container lifecycle) | Scheduler Agent (node within ADK Workflow) |
| **Worker Discovery** | Polls Server for claimable Intents | Reads blackboard state and judges autonomously |
| **Concurrency Control** | Project.reason lease (one reason per project) | ADK session-level state lock + max_concurrent_workers config |
| **Timeout Strategy** | per-task-type timeout (bootstrap/reason/explore) | per-Worker timeout + global workflow timeout |
| **Fault Tolerance** | Intent worker cleared + re-claimed | Checkpoint rollback + human intervention |

---

## 4. Dynamic Workflow in Phase 2+

### 4.1 Dynamic Workflow Connection Point

After Phase 2 (Scheduler + blackboard initialization) completes, the workflow enters the **Dynamic Workflow phase**. Unlike Static Graph's compile-time determination, Dynamic Workflow **builds nodes at runtime**, supporting loops, recursion, and complex conditional branching [^28^].

```
+--------------------------------------------------------------------------+
|                     Phase 2: Static Graph complete                        |
|   +-------------+    +-------------+    +-------------+                |
|   |  Phase 0    |--->|  Phase 1    |--->|  Scheduler  |                |
|   |  (Static)   |    |  (Static)   |    |  (Static)   |                |
|   +-------------+    +-------------+    +------+------+                |
|                                                |                       |
|                          Human confirms Top N functions                  |
|                          Writes to blackboard                            |
|                                                |                       |
|                                                v                       |
|   +------------------------------------------------------------------+ |
|   |              Phase 3+: Dynamic Workflow (Runtime)                | |
|   |                                                                  | |
|   |   +-----------------+                                           | |
|   |   |  Context Builder| <- Reads blackboard, builds context       | |
|   |   |  (FunctionNode) |                                           | |
|   |   +--------+--------+                                           | |
|   |            v                                                     | |
|   |   +-----------------+     +-----------------+                  | |
|   |   |  Dynamic Router |---->| Func Analyzer   |                  | |
|   |   |  (FunctionNode) |     |  #1 (Agent)     |                  | |
|   |   |                 |     +--------+--------+                  | |
|   |   | Decide next path|              |                           | |
|   |   | based on bb     |     +--------v--------+                  | |
|   |   +-----------------+     |  Loop / Verify  |                  | |
|   |            |              |  (FunctionNode) |                  | |
|   |            |              |                 |                  | |
|   |            |              |  Iterate verify |                  | |
|   |            |              |  high confidence|                  | |
|   |            |              +--------+--------+                  | |
|   |            |                       |                           | |
|   |            +-----------------------+                           | |
|   |                                    |                           | |
|   |                           +--------v--------+                  | |
|   |                           |  Report Generator|                  | |
|   |                           |   (Agent)        |                  | |
|   |                           +-----------------+                  | |
|   |                                                                  | |
|   +------------------------------------------------------------------+ |
|                                                                          |
|   <------ HITL points: Strategic / Tactical / Review --------------->  |
|                                                                          |
+--------------------------------------------------------------------------+
```

### 4.2 Runtime Node Construction Patterns

Dynamic Workflow's core capability is **programmatically building workflow nodes in code**, rather than pre-defining edges tuples. Key patterns include:

**Pattern A: Dynamic Node Creation Based on Blackboard State**

Human confirms N functions for deep analysis; dynamically create N Function Deep Analyzer nodes at runtime:

```python
# Pseudocode -- runtime node construction pattern
async def dynamic_phase_entry(ctx: Context):
    blackboard = ctx.session.state["blackboard"]
    approved = blackboard["facts"]["f_007_human_approval"]["approved_functions"]
    
    # Dynamically build analysis nodes at runtime
    for func_addr in approved:
        analyzer = Agent(
            name=f"func_analyzer_{func_addr}",
            instruction=build_func_analysis_prompt(func_addr),
            tools=[load_decompile, load_disassembly]
        )
        # Execute dynamically via ctx.run_node()
        result = await ctx.run_node(analyzer)
        # Write result back to blackboard
        write_fact(blackboard, f"f_func_deep_{func_addr}", result)
```

**Pattern B: Iterative Verification Loop**

Automatically verify high-confidence findings with conditional termination:

```python
# Pseudocode -- iterative verification loop
async def verification_loop(ctx: Context):
    blackboard = ctx.session.state["blackboard"]
    max_iterations = 3
    
    for i in range(max_iterations):
        # Read current pending verifications
        pending = find_high_confidence_unverified(blackboard)
        if not pending:
            break  # All verified, terminate loop
            
        # Dynamically create verification node
        verifier = Agent(name=f"verifier_round_{i}", ...)
        result = await ctx.run_node(verifier)
        
        # Write back verification result
        write_fact(blackboard, f"f_verification_round_{i}", result)
        
        # Check if human intervention needed
        if result["needs_human_review"]:
            yield RequestInput(message="Verification conflict found, please review", ...)
```

**Pattern C: Conditional Branch Routing**

Conditional judgment based on blackboard state, dynamically selecting execution paths:

```python
# Pseudocode -- conditional branching
async def dynamic_router(ctx: Context):
    blackboard = ctx.session.state["blackboard"]
    sample_type = detect_sample_type_from_blackboard(blackboard)
    
    if sample_type == "lnk":
        # Dynamically load LNK Analyzer
        lnk_analyzer = Agent(name="lnk_analyzer", ...)
        return await ctx.run_node(lnk_analyzer)
    elif sample_type == "loader_chain":
        # Enter multi-sample correlation analysis path
        return await run_multi_sample_analysis(ctx)
    else:
        # Standard single-sample analysis path
        return await run_standard_analysis(ctx)
```

### 4.3 Handoff from Static Graph

The transition from Phase 2 (Static Graph endpoint) to Phase 3 (Dynamic Workflow start) is achieved through **Blackboard Handoff**:

1. The Static Graph's Scheduler Agent completes its final step, writing all 5 Worker outputs as Facts to the blackboard
2. The Scheduler triggers a **strategic HITL** (human confirms analysis direction and Top N functions)
3. Human confirmation results are written to the blackboard (`f_007_human_approval`)
4. The Dynamic Workflow's entry node (Context Builder) reads the blackboard and constructs the Phase 3+ execution context
5. All subsequent Dynamic nodes continuously read/write the blackboard via `ctx.session.state["blackboard"]`

---

## 5. Human Intervention at Any Time

### 5.1 Three-Level Intervention Mechanism

Drawing on Cairn's **Hint annotation mechanism** [^7^] and ADK's `RequestInput` node [^25^], a three-level human intervention system is designed:

| Level | Name | Trigger Timing | Intervention Capability | ADK Implementation |
|-------|------|----------------|------------------------|-------------------|
| **L1** | **Strategic** | After Phase 0/1, before Phase 3 starts | Correct behavior classification, adjust Top N functions, inject analysis strategy Hints | `RequestInput` + payload (full context) |
| **L2** | **Tactical** | During Dynamic Workflow execution | Approve/reject dynamically created Intents, modify loop termination conditions, force skip a function | `RequestInput` + response_schema (structured reply) |
| **L3** | **Review** | After any Worker produces high-risk findings | Review specific findings, request re-verification, inject targeted Hints | `RequestInput` + payload (finding details) |

### 5.2 Intervention Point Design

**Strategic Intervention (L1)** triggers after Phase 2 ends, with payload carrying complete Phase 0+1 analysis results:

```python
# Strategic HITL node example
async def strategic_hitl(ctx: Context):
    blackboard = ctx.session.state["blackboard"]
    
    # Assemble complete context from blackboard
    payload = {
        "behavior_profile": get_latest_fact(blackboard, "behavior_profile"),
        "top_candidates": get_latest_fact(blackboard, "function_boundary_analysis"),
        "risk_findings": extract_high_risk_facts(blackboard),
        "checklist_status": get_checklist_completion(blackboard)
    }
    
    yield RequestInput(
        message="Phase 0/1 analysis complete. Please confirm analysis direction and key functions",
        payload=payload,
        response_schema=StrategicApprovalInput  # Pydantic schema constrains reply
    )
    # User reply passed to next step via node_input
```

**Tactical Intervention (L2)** triggers dynamically during Dynamic Workflow execution. Workers can request human input at any time:

```python
# Worker requests human clarification during execution
async def func_analyzer_with_hitl(ctx: Context):
    # ... perform analysis ...
    if confidence == "low" and needs_clarification:
        yield RequestInput(
            message=f"Function {func_addr} has low confidence. Please provide additional info",
            payload={"current_analysis": partial_result, "uncertainty": reasons},
            response_schema=TacticalInput
        )
    # Human reply serves as supplementary context to continue analysis
```

**Review Intervention (L3)** is triggered by Scheduler situation assessment. When high-risk findings are detected, automatically pause:

```python
# Scheduler situation assessment + auto-trigger review
async def scheduler_situation_assessment(ctx: Context):
    blackboard = ctx.session.state["blackboard"]
    
    # Scan for high-risk findings on blackboard
    high_risk = scan_for_high_risk(blackboard)
    
    if high_risk and not has_been_reviewed(high_risk):
        # Auto-trigger L3 review
        yield RequestInput(
            message=f"Detected {len(high_risk)} high-risk findings. Please review",
            payload={"findings": high_risk},
            response_schema=ReviewApprovalInput
        )
```

### 5.3 Blackboard and Human Interaction

All human operations are ultimately reflected as writes to the blackboard:

| Human Operation | Blackboard Write |
|-----------------|-----------------|
| Confirm analysis direction | Append `f_xxx_human_approval` Fact |
| Modify Top N functions | Append `f_xxx_human_modified_candidates` Fact (mark supersedes old version) |
| Inject strategy Hint | Append new Hint to `hints/` namespace |
| Request re-verification | Append `i_xxx_reverify_target` Intent |
| Skip a function | Append `h_xxx_skip_function` Hint |
| Terminate analysis | Write `meta.execution_phase = "terminated_by_human"` |

---

## 6. Event System and Data Flow

### 6.1 ADK Event Three-Parameter Mapping

ADK Graph Workflow's `Event` object carries three types of data [^9^], mapped in this architecture as:

| Event Parameter | Purpose | Data in This Architecture |
|-----------------|---------|--------------------------|
| **`output`** | Inter-node data passing | Worker-produced structured analysis results (JSON) |
| **`message`** | Content displayed to user | HITL prompt text, progress notifications, risk alerts |
| **`state`** | Cross-node persistent data | **Blackboard state** (`blackboard` namespace) |

### 6.2 Data Flow Panorama

```
+-----------------------------------------------------------------------------+
|                           Data Flow Architecture                             |
|                                                                             |
|   Input (sample export dir)                                                 |
|      |                                                                      |
|      v                                                                      |
|   +---------------------------------------------------------------------+   |
|   |                    Phase 0/1: Static Graph                           |   |
|   |                                                                      |   |
|   |   FunctionTool --> Worker Agent --> Event.output (analysis result)  |   |
|   |       |                |                                            |   |
|   |       |                +------------+                               |   |
|   |       |                             v                               |   |
|   |       +-------------------> Event.state["blackboard"] (write bb)    |   |
|   |                                                                      |   |
|   +---------------------------------------------------------------------+   |
|                                  |                                          |
|                                  v                                          |
|   +---------------------------------------------------------------------+   |
|   |                   Phase 2: Scheduler + Blackboard                    |   |
|   |                                                                      |   |
|   |   Read blackboard --> Situation assessment --> HITL trigger         |   |
|   |       |                                              |              |   |
|   |       |                              Event.message (human prompt)   |   |
|   |       |                              Event.state (bb snapshot)      |   |
|   |       |                                              |              |   |
|   |       +------------------<---------------------------+              |   |
|   |                (human reply writes to blackboard)                    |   |
|   +---------------------------------------------------------------------+   |
|                                  |                                          |
|                                  v                                          |
|   +---------------------------------------------------------------------+   |
|   |                  Phase 3+: Dynamic Workflow                          |   |
|   |                                                                      |   |
|   |   Context Builder --> Dynamic Router --> Runtime Nodes              |   |
|   |       |                    |                    |                   |   |
|   |       |                    |                    +---> Event.output   |   |
|   |       |                    |                    +---> Event.message |   |
|   |       |                    |                    +---> Event.state    |   |
|   |       |                    |                         (blackboard)   |   |
|   |       +--------------------+-------------------------<---------------+   |
|   |                   (loop read/write blackboard)                       |   |
|   +---------------------------------------------------------------------+   |
|                                                                             |
+-----------------------------------------------------------------------------+
```

---

## 7. Directory Structure

```
multi_agent_adk/
+-- agent.py                          # Root workflow (Static Graph + Dynamic entry)
+-- pyproject.toml                    # Dependencies (added: google-adk>=2.0)
+-- .env                              # GOOGLE_API_KEY
+-- ARCHITECTURE.md                   # v2.0 architecture guide
+-- ARCHITECTURE_BLUEPRINT.md         # v3.0 architecture blueprint (this file)
|
+-- blackboard/                       # NEW: Shared blackboard state space
|   +-- __init__.py
|   +-- core.py                       # Blackboard core: read/write/append/checkpoint
|   +-- facts.py                      # Fact management: create, supersedes chain, history
|   +-- intents.py                    # Intent management: declare, claim, complete
|   +-- hints.py                      # Hint management: inject, query, expire
|   +-- index.py                      # Index layer: fast query, tag mapping
|
+-- tools/                            # FunctionTool implementations
|   +-- __init__.py
|   +-- file_loaders.py               # IDA export file loaders
|   +-- pe_utils.py                   # PE utilities
|   +-- archiver.py                   # NEW: Worker output archiver (P2 extension)
|
+-- workers/                            # Worker Agent definitions
|   +-- __init__.py
|   +-- shared_prompts.py             # Five-section prompt templates
|   |
|   +-- phase0/                       # Phase 0: Triage (Static Graph)
|   |   +-- __init__.py
|   |   +-- string_artifact_analyst.py
|   |   +-- api_behavior_profiler.py
|   |   +-- export_interface_analyzer.py
|   |
|   +-- phase1/                       # Phase 1: Profiling (Static Graph)
|   |   +-- __init__.py
|   |   +-- behavior_profile_synthesizer.py
|   |   +-- function_boundary_detector.py
|   |
|   +-- phase2/                       # NEW: Phase 2 Dynamic Analysis (Dynamic Workflow)
|   |   +-- __init__.py
|   |   +-- context_builder.py        # Dynamic phase context building
|   |   +-- dynamic_router.py         # Runtime routing decisions
|   |   +-- function_deep_analyzer.py # Function-level deep analysis (dynamic instancing)
|   |   +-- verification_agent.py     # Verification Worker (iterative loop)
|   |   +-- report_generator.py       # ALL_IN_ONE report generation
|   |
|   +-- optional/                       # Optional Workers
|       +-- __init__.py
|       +-- lnk_analyzer.py           # LNK sample analysis (conditional load)
|
+-- scheduler/                          # NEW: Scheduler module
|   +-- __init__.py
|   +-- scheduler_agent.py            # Scheduler Agent (blackboard maintainer)
|   +-- situation_assessment.py       # Situation assessment engine
|   +-- lifecycle_manager.py          # Workflow lifecycle management
|
+-- hitl/                               # NEW: Human intervention module
|   +-- __init__.py
|   +-- strategic_hitl.py             # L1 Strategic intervention
|   +-- tactical_hitl.py              # L2 Tactical intervention
|   +-- review_hitl.py                # L3 Review intervention
|   +-- command_parser.py             # Human command parser (CONFIRM/MODIFY/INJECT/STOP)
|
+-- callbacks/                          # Callback functions
|   +-- __init__.py
|
+-- tests/                              # Tests
    +-- __init__.py
    +-- test_tools.py
    +-- test_workers.py
    +-- test_blackboard.py            # NEW: Blackboard state tests
    +-- test_dynamic_workflow.py      # NEW: Dynamic Workflow tests
    +-- test_integration.py
```

---

## 8. Key Interface Contracts

### 8.1 Blackboard Core API

```python
# blackboard/core.py -- Core read/write interface

class Blackboard:
    """
    Shared blackboard state space -- drawing on Cairn's append-only idea,
    adapted for ADK session state
    """
    
    def write_fact(
        self,
        fact_id: str,
        content: dict,
        worker: str,
        tags: list[str] = None,
        supersedes: str | None = None
    ) -> None:
        """Write new Fact -- append-only, supports supersedes chain"""
        
    def read_facts(
        self,
        worker: str | None = None,
        tags: list[str] | None = None,
        latest_only: bool = True
    ) -> list[Fact]:
        """Read Facts -- filter by Worker, tags; option to read only latest versions"""
        
    def declare_intent(
        self,
        intent_id: str,
        description: str,
        from_facts: list[str],
        worker: str
    ) -> None:
        """Declare new Intent -- manifestation of Worker autonomous decision-making"""
        
    def inject_hint(
        self,
        hint_id: str,
        content: str,
        creator: str,
        target_workers: list[str] | None = None
    ) -> None:
        """Inject Hint -- human or Worker provides strategy guidance"""
        
    def checkpoint(self, label: str) -> str:
        """Save blackboard snapshot -- supports rollback to any historical state"""
        
    def rollback(self, checkpoint_id: str) -> None:
        """Rollback to specified snapshot -- undo capability after human intervention"""
```

### 8.2 Scheduler API

```python
# scheduler/scheduler_agent.py

class SchedulerAgent:
    """
    Blackboard maintainer + situation assessor
    Responsibilities:
    1. Maintain blackboard consistency (version, index, supersedes chain)
    2. Periodic situation assessment (scan for high-risk, confidence conflicts, coverage gaps)
    3. Trigger HITL (L1/L2/L3 level judgment)
    4. Manage Static -> Dynamic phase transition
    5. Checkpoint snapshot management
    """
    
    async def run(self, ctx: Context) -> Event:
        """
        Scheduler main loop:
        1. Read current blackboard state
        2. Execute situation assessment
        3. Determine if HITL needed
        4. Decide next phase execution path
        5. Write decision Fact
        """
```

### 8.3 Dynamic Workflow Entry

```python
# agent.py -- Phase 3+ Dynamic Workflow entry

from google.adk import Workflow, Agent
from google.adk.events import RequestInput

# Phase 0/1: Static Graph (compile-time deterministic)
static_workflow = Workflow(
    name="phase0_1_static",
    edges=[
        (START, (string_artifact_analyst, api_behavior_profiler, export_interface_analyzer)),
        ((string_artifact_analyst, api_behavior_profiler, export_interface_analyzer),
         (behavior_profile_synthesizer, function_boundary_detector)),
        ((behavior_profile_synthesizer, function_boundary_detector), scheduler_agent),
    ]
)

# Phase 2: Scheduler + HITL (Static node, but behavior based on blackboard state)
# Phase 3+: Dynamic Workflow (runtime construction)
async def dynamic_phase_entry(ctx: Context):
    """Dynamic Workflow entry -- build execution path at runtime based on blackboard state"""
    blackboard = ctx.session.state["blackboard"]
    
    # Build Phase 3 context
    context = await build_dynamic_context(blackboard)
    
    # Dynamic routing decision
    route = await dynamic_router(ctx, context)
    
    # Execute dynamic nodes based on routing result
    if route == "function_deep_analysis":
        return await run_function_deep_analysis(ctx, context)
    elif route == "verification_loop":
        return await run_verification_loop(ctx, context)
    elif route == "multi_sample":
        return await run_multi_sample_analysis(ctx, context)
    else:
        return await run_report_generation(ctx, context)
```

---

## 9. Design Principles and Constraints

### 9.1 Core Principles

| Principle | Description | Source |
|-----------|-------------|--------|
| **Blackboard First** | Workers do not communicate directly; all coordination through blackboard indirectly | Cairn stigmergy [^7^] |
| **Append-Only** | State changes expressed by adding new Facts; history fully preserved | Cairn Fact model [^7^] |
| **Decentralized Decision-Making** | Workers autonomously read blackboard and judge; Scheduler only maintains situation | Cairn OODA loop [^8^] |
| **Determinism First** | Phase 0/1 use Static Graph for compile-time verifiability | ADK Graph [^2^] |
| **Dynamic Supplement** | Phase 2+ use Dynamic Workflow for runtime uncertainty | ADK Dynamic [^28^] |
| **Human Sovereignty** | Humans can intervene at any breakpoint; final decision authority always belongs to humans | ADK RequestInput [^25^] |
| **Token Observability** | Full-stage Token consumption statistics, supporting cost control | v2.0 existing principle |

### 9.2 Key Constraints

**State Consistency Constraints**:
- Blackboard writes must be atomic operations (single ADK session state update)
- Concurrent write conflicts detected via version numbers (optimistic locking)
- Workers reading the blackboard obtain a **snapshot**, not a live view, avoiding state drift during execution

**HITL Constraints**:
- Each HITL pause must carry a complete blackboard snapshot (payload)
- Human replies must be structured via `response_schema`; free text parsing is prohibited
- Post-HITL timeout default behavior is configurable (continue / terminate / degrade to auto-decision)

**Dynamic Workflow Constraints**:
- Dynamically created nodes must inherit parent node security context (tool permissions, model config)
- Loops must set maximum iteration caps to prevent infinite loops
- Dynamic node exceptions must be caught and written to blackboard; silent failures are prohibited

### 9.3 Differences from Cairn Summary

This architecture **is not a re-implementation of Cairn**, but **selectively draws on its design ideas**:

| Cairn Feature | This Architecture Approach | Reason |
|--------------|---------------------------|--------|
| Complete Fact/Intent/Hint graph model | Simplified to blackboard namespace (facts/intents/hints/) | No cross-process REST API needed; ADK session state is sufficient |
| Dispatcher independent process | Scheduler Agent (node within Workflow) | Monolithic agent; no distributed scheduling needed |
| Multiple Workers competing for Intents | Sequential execution + blackboard state-driven | ADK session model does not support multi-process competition |
| Container lifecycle management | Not involved (local execution) | No containerized deployment requirement |
| Project.reason lease | Scheduler situation assessment + HITL trigger | Simplified concurrency control |

---

## 10. Extension Roadmap Architecture Mapping

Mapping v2.0's P1/P2/P3 extension items to positions in the v3.0 architecture:

| Extension Item | v2.0 Priority | v3.0 Architecture Position | Key Technology |
|---------------|--------------|---------------------------|----------------|
| **Skill knowledge refinement** | P1 | Worker prompts (unchanged) | Five-section prompt templates |
| **Function-level deep analysis Worker** | P1 | `workers/phase2/function_deep_analyzer.py` | Dynamic Workflow runtime instancing |
| **Dynamic Worker construction** | P1 | `scheduler/lifecycle_manager.py` + Dynamic Router | `ctx.run_node()` dynamic execution |
| **Verification Worker** | P2 | `workers/phase2/verification_agent.py` | Iterative loop + HITL trigger |
| **ALL_IN_ONE generation Worker** | P2 | `workers/phase2/report_generator.py` | Blackboard facts aggregation |
| **Archive output** | P2 | `tools/archiver.py` | Blackboard history serialization |
| **LNK optional sub-Agent** | P2 | `workers/optional/lnk_analyzer.py` | Conditional branch loading |
| **Multi-sample correlation analysis** | P3 | `workers/phase2/multi_sample/` | Blackboard cross-sample index |
| **Web UI review interface** | P3 | HITL payload external rendering | Independent frontend project |
| **PE header/section analysis** | P3 | `workers/phase0/pe_header_analyzer.py` | Static Graph new node |

---

## 11. Dependency Update

```toml
[project]
name = "multi-agent-adk"
version = "0.2.0"
requires-python = ">=3.11"  # ADK 2.0 requires Python 3.11+
dependencies = [
    "google-adk>=2.0.0",      # ADK 2.0 GA -- Graph + Dynamic Workflow + RequestInput
    "pydantic>=2.0",
    "python-dotenv>=1.0",
]
```

> `pefile`, `capstone`, and other binary parsing libraries **remain non-ADK dependencies**. `pe_info.json` generation scripts can independently install and run these libraries.
