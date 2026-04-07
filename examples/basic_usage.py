"""
Basic usage examples for Agent Blame-Finder.

This file demonstrates how to use Agent Blame-Finder to:
1. Track multi-agent execution with JEP receipts
2. Build causality chains with JAC (task_based_on)
3. Analyze incidents to find who's responsible
4. Verify signatures and chain integrity
"""

import time
import json
from blame_finder import BlameFinder


# ============================================================
# Example 1: Single Agent Tracking
# ============================================================

def example_single_agent():
    """Demonstrate basic agent tracking with a single agent."""
    print("\n" + "="*60)
    print("Example 1: Single Agent Tracking")
    print("="*60)

    finder = BlameFinder(storage="./examples_logs")

    @finder.trace(agent_name="WeatherAgent")
    def get_weather(city: str) -> str:
        """Simulate an agent that fetches weather."""
        # Simulate API call
        time.sleep(0.1)
        return f"Weather in {city}: Sunny, 72°F"

    # Execute the agent
    result = get_weather("San Francisco")
    print(f"Result: {result}")

    # Show the JEP receipt
    receipt_hash = list(finder.receipts.keys())[0]
    receipt = finder.receipts[receipt_hash]
    print(f"\n📝 JEP Receipt created:")
    print(f"   Hash: {receipt_hash[:16]}...")
    print(f"   Agent: {receipt.who}")
    print(f"   Verb: {receipt.verb.value}")
    print(f"   Timestamp: {receipt.when}")


# ============================================================
# Example 2: Multi-Agent Chain (JAC Causality)
# ============================================================

def example_multi_agent_chain():
    """Demonstrate JAC causality chain with task_based_on linking."""
    print("\n" + "="*60)
    print("Example 2: Multi-Agent Chain with JAC Causality")
    print("="*60)

    finder = BlameFinder(storage="./examples_logs")

    # Root task hash (simulates a parent task ID from a planner)
    root_task_hash = "task-planner-001"

    @finder.trace(agent_name="PlannerAgent", parent_task_hash=root_task_hash)
    def plan_task(requirement: str) -> str:
        """Planner agent breaks down requirements."""
        return "Plan: Step1 -> Step2 -> Step3"

    @finder.trace(agent_name="ExecutorAgent", parent_task_hash=None)  # Will be set dynamically
    def execute_step(step: str) -> str:
        """Executor agent performs a step."""
        if step == "Step3":
            raise ValueError("Execution failed at Step3!")
        return f"Executed: {step}"

    # Execute the chain
    print("Executing multi-agent workflow...")
    plan = plan_task("Build a web app")
    print(f"Planner output: {plan}")

    # Get the planner's receipt hash to use as parent
    planner_hash = None
    for h, trace in finder.traces.items():
        if trace.agent_name == "PlannerAgent":
            planner_hash = h
            break

    if planner_hash:
        # Redecorate executor with the correct parent
        @finder.trace(agent_name="ExecutorAgent", parent_task_hash=planner_hash)
        def execute_step_with_parent(step: str) -> str:
            if step == "Step3":
                raise ValueError("Execution failed at Step3!")
            return f"Executed: {step}"

        try:
            execute_step_with_parent("Step1")
            execute_step_with_parent("Step2")
            execute_step_with_parent("Step3")  # This will fail
        except ValueError as e:
            print(f"\n❌ Error occurred: {e}")

    # Show the causality chain
    print("\n📊 JAC Causality Chain:")
    for h, trace in finder.traces.items():
        print(f"   Agent: {trace.agent_name}")
        print(f"      Status: {trace.status}")
        print(f"      Parent Task: {trace.parent_task_hash}")
        print(f"      Receipt Hash: {h[:16]}...")


# ============================================================
# Example 3: Blame Analysis (Find Who Messed Up)
# ============================================================

def example_blame_analysis():
    """Demonstrate blame analysis to find responsible agent."""
    print("\n" + "="*60)
    print("Example 3: Blame Analysis - Find Who Messed Up")
    print("="*60)

    finder = BlameFinder(storage="./examples_logs")

    # Create a chain of agents
    @finder.trace(agent_name="PM-Agent")
    def assign_task(requirement: str) -> str:
        """PM agent assigns task."""
        return f"Task assigned: {requirement}"

    @finder.trace(agent_name="Coder-Agent")
    def write_code(requirement: str) -> str:
        """Coder agent writes code."""
        # Simulate a bug in the coder agent
        if "critical" in requirement.lower():
            return "ERROR: Failed to parse requirement"
        return "print('hello world')"

    @finder.trace(agent_name="Verifier-Agent")
    def verify_code(code: str) -> bool:
        """Verifier agent checks code quality."""
        return "ERROR" not in code

    # Execute the workflow
    print("Executing agent workflow...")
    task = assign_task("Build a critical feature")
    print(f"PM: {task}")

    code = write_code(task)
    print(f"Coder: {code[:50]}...")

    is_valid = verify_code(code)
    print(f"Verifier: {'PASS' if is_valid else 'FAIL'}")

    # Get the coder's receipt hash for blame analysis
    coder_hash = None
    for h, trace in finder.traces.items():
        if trace.agent_name == "Coder-Agent":
            coder_hash = h
            break

    if coder_hash:
        # Analyze who's responsible for the failure
        result = finder.blame(coder_hash)
        print("\n" + "="*40)
        print("🔍 BLAME ANALYSIS RESULT")
        print("="*40)
        print(f"Incident: {result['incident'][:16]}...")
        print(f"Verdict: {result['verdict']}")
        print(f"Reason: {result['reason']}")
        print(f"Confidence: {result.get('confidence', 0)*100:.0f}%")

        if "chain" in result:
            print("\nResponsibility Chain:")
            for i, node in enumerate(result["chain"]):
                icon = "✅" if node["status"] == "success" else "❌" if node["status"] == "failed" else "⏳"
                print(f"   {i+1}. {icon} {node['agent']} - {node['status']}")


# ============================================================
# Example 4: Signature Verification
# ============================================================

def example_signature_verification():
    """Demonstrate cryptographic signature verification."""
    print("\n" + "="*60)
    print("Example 4: Cryptographic Signature Verification")
    print("="*60)

    finder = BlameFinder(storage="./examples_logs")

    @finder.trace(agent_name="TrustedAgent")
    def make_decision(input_data: str) -> str:
        return f"Decision based on: {input_data}"

    # Execute
    result = make_decision("Sensitive data")
    print(f"Result: {result}")

    # Get the receipt
    receipt_hash = list(finder.receipts.keys())[0]
    receipt = finder.receipts[receipt_hash]

    print(f"\n📝 Receipt Hash: {receipt_hash[:32]}...")
    print(f"   Signature present: {receipt.signature is not None}")

    # Verify signature
    public_key = finder._get_agent_public_key(receipt.who)
    is_valid = receipt.verify(public_key)

    print(f"\n🔐 Signature Verification:")
    print(f"   Agent: {receipt.who}")
    print(f"   Status: {'✅ VALID' if is_valid else '❌ INVALID'}")

    # Show that tampering would be detected
    print("\n⚠️ If someone tampered with the receipt:")
    print("   The hash would change and signature verification would fail")


# ============================================================
# Example 5: Causality Tree Visualization
# ============================================================

def example_causality_tree():
    """Demonstrate building a causality tree from receipts."""
    print("\n" + "="*60)
    print("Example 5: Causality Tree Visualization")
    print("="*60)

    finder = BlameFinder(storage="./examples_logs")

    # Build a tree: Root -> Child1 -> Child2
    @finder.trace(agent_name="RootAgent")
    def root_task():
        return "root result"

    root_task()

    # Get root hash
    root_hash = None
    for h, trace in finder.traces.items():
        if trace.agent_name == "RootAgent":
            root_hash = h
            break

    if root_hash:
        # Add child tasks with parent reference
        @finder.trace(agent_name="ChildAgent", parent_task_hash=root_hash)
        def child_task():
            return "child result"

        child_task()

        # Add grandchild
        child_hash = None
        for h, trace in finder.traces.items():
            if trace.agent_name == "ChildAgent":
                child_hash = h
                break

        if child_hash:
            @finder.trace(agent_name="GrandChildAgent", parent_task_hash=child_hash)
            def grandchild_task():
                return "grandchild result"

            grandchild_task()

        # Build and display causality tree
        tree = finder.get_causality_tree(root_hash)
        print("\n🌲 Causality Tree:")
        print_tree(tree)


def print_tree(node, indent=0):
    """Helper function to pretty print a causality tree."""
    prefix = "  " * indent
    if node.get("missing"):
        print(f"{prefix}❌ [MISSING] {node['hash'][:16]}...")
        return

    agent = node.get("agent", "unknown")
    verb = node.get("verb", "?")
    hash_short = node.get("hash", "")[:16] + "..." if node.get("hash") else "no-hash"

    print(f"{prefix}📦 {agent} ({verb}) - {hash_short}")

    for child in node.get("children", []):
        print_tree(child, indent + 1)


# ============================================================
# Example 6: CLI Commands Demo
# ============================================================

def example_cli_commands():
    """Demonstrate how to use CLI commands."""
    print("\n" + "="*60)
    print("Example 6: CLI Commands Reference")
    print("="*60)

    print("""
You can use the following CLI commands after installation:

1. Analyze an incident:
   $ blame-finder blame <incident-hash>

2. Launch the visual dashboard:
   $ blame-finder dashboard --port 8080

3. Show causality tree:
   $ blame-finder tree <root-hash>

4. Verify a receipt:
   $ blame-finder verify <receipt-hash>

Example:
   $ blame-finder blame abc123def456
   $ blame-finder dashboard
   $ blame-finder tree task-root-001
   $ blame-finder verify receipt-hash-789
    """)


# ============================================================
# Main: Run All Examples
# ============================================================

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║     Agent Blame-Finder - Usage Examples                     ║
║     "Find out which Agent messed up in 3 seconds."          ║
╚══════════════════════════════════════════════════════════════╝
    """)

    # Run examples (comment out to run selectively)
    example_single_agent()
    example_multi_agent_chain()
    example_blame_analysis()
    example_signature_verification()
    example_causality_tree()
    example_cli_commands()

    print("\n" + "="*60)
    print("✅ All examples completed!")
    print("="*60)
    print("\n💡 Tip: Check the './examples_logs' directory for stored JEP receipts.")
    print("   You can use 'blame-finder dashboard' to visualize the data.")
