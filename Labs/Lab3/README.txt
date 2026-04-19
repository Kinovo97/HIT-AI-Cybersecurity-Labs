# Lab 3: Simple Tool-Using AI Agent

## Group Information
- Sharon Weisman (208660456)
- Rom Ben Yakar (207295437)

## The Agentic Loop
The agent operates in a continuous loop as follows:
1. User Input: Receives a raw security log or event description.
2. Agent Reasoning: The agent identifies that the input requires technical analysis.
3. Tool Call: The agent executes the 'analyze_log()' tool.
4. Tool Result: The tool returns structured data (Severity, Category, and Patterns).
5. Final Explanation: The agent synthesizes the tool's output into a human-readable security advisory.

## Implementation Details
- File: Lab3_Agent.ipynb
- Tool Logic: Rule-based pattern matching for Brute Force (T1110), Malware, and SQL Injection.
- Output: Structured dictionary containing severity levels and recommended mitigation actions.

## How to Run
1. Open 'Lab3_Agent.ipynb' in VS Code or Jupyter.
2. Ensure the 'typing' library is available (standard in Python 3.5+).
3. Run the cells to see the Agent process various test cases, including failed logins and suspicious SQL queries.