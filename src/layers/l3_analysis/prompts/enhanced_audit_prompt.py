"""
Enhanced Security Audit Prompts - P8-08b Component

This module implements enhanced prompts with anti-hallucination rules
derived from the code-audit skill at /opt/AI/code-audit/.

Core Philosophy: Better to miss a vulnerability than report a false positive.

Components:
- ANTI_HALLUCINATION_RULES: Strict verification requirements
- EXECUTION_EVIDENCE_REQUIREMENTS: Specific evidence per vulnerability type
- FEW_SHOT_EXAMPLES: Correct vs incorrect reporting examples

Integration:
    Used by build_audit_prompt() in security_audit.py when use_enhanced_prompt=True
"""

# =============================================================================
# ANTI-HALLUCINATION RULES (来自 code-audit skill)
# =============================================================================

ANTI_HALLUCINATION_RULES = """
## ⚠️ Anti-Hallucination Rules (CRITICAL - MUST FOLLOW)

### Rule 1: Verify Code Execution
ONLY report a vulnerability if ALL of the following are true:
✓ User-controlled input exists (request param, user input, env var)
✓ The input reaches a dangerous operation WITHOUT sanitization
✓ The dangerous operation is ACTUALLY executed

DO NOT report if:
✗ Only string concatenation/return (no actual file operation)
✗ Method only constructs objects but never calls dangerous methods
✗ Parameters are unused or only logged

### Rule 2: Verify File Existence
✓ MUST reference actual code from the provided snippet
✗ DO NOT assume additional files exist based on "typical project structure"

### Rule 3: Confidence Calibration
| Confidence | Required Evidence |
|------------|-------------------|
| 0.9-1.0 | Working PoC + clear attack path |
| 0.7-0.9 | Clear data flow + actual dangerous call |
| 0.5-0.7 | Dangerous pattern but uncertain execution |
| 0.3-0.5 | Suspicious pattern only → suspicious_code |
| 0.0-0.3 | Too uncertain → skip or suspicious_code |

**Core Principle: Better to miss a vulnerability than report a false positive.**
"""


# =============================================================================
# EXECUTION EVIDENCE REQUIREMENTS
# =============================================================================

EXECUTION_EVIDENCE_REQUIREMENTS = """
## Execution Evidence Requirements

For each vulnerability type, specific evidence is required:

### SQL Injection
- Evidence: User input reaches database query WITHOUT parameterization
- Must show: `execute("... " + user_input)` or similar
- NOT evidence: String concatenation without database call
- Safe patterns: Parameterized queries, prepared statements, ORM methods

### Command Injection
- Evidence: User input reaches system command execution
- Must show: `.exec()`, `.start()`, `Runtime.exec()`, `os.system()`, etc.
- NOT evidence: Only constructing ProcessBuilder
- Safe patterns: Shell escape functions, allow-lists

### Path Traversal
- Evidence: User input reaches file operation
- Must show: `Files.read()`, `FileInputStream()`, `open()`, etc.
- NOT evidence: Only string concatenation with file name
- Safe patterns: Path validation, basename/dirname, allow-lists

### XSS (Cross-Site Scripting)
- Evidence: User input reaches HTML rendering
- Must show: `innerHTML`, `dangerouslySetInnerHTML`, template rendering without escape
- NOT evidence: JSON response, error message, logging
- Safe patterns: Auto-escaping templates, textContent, JSON encoding

### Deserialization
- Evidence: User-controlled data reaches deserialization
- Must show: `pickle.loads()`, `yaml.load()`, `ObjectInputStream()`, etc.
- NOT evidence: Deserializing trusted constants
- Safe patterns: Safe loaders (yaml.safe_load), allow-lists

### Code Injection
- Evidence: User input reaches code execution
- Must show: `eval()`, `exec()`, `compile()`, `Runtime.exec()`, etc.
- NOT evidence: Only string operations
- Safe patterns: Avoid eval entirely, use allow-lists
"""


# =============================================================================
# FEW-SHOT EXAMPLES (正反例对比)
# =============================================================================

FEW_SHOT_EXAMPLES = """
## Examples: Correct vs Incorrect Reporting

### ❌ WRONG: Reporting Non-Executable Pattern
```java
public String handleUpload(String file) {
    return "File uploaded: " + file;  // Only returns string
}
```
**Don't report**: "Path Traversal"
**Do**: Skip or add to suspicious_code with "requires actual file operation"

### ✅ CORRECT: Reporting Executable Pattern
```java
public String readFile(String path) {
    return Files.readString(Paths.get(path));  // Actual file read!
}
```
**Report**: "Path Traversal - user input reaches Files.readString()"

### ❌ WRONG: Reporting Construction Only
```python
shell = ProcessBuilder(cmd)  # Only constructed, never started
```
**Don't report**: "Command Injection"
**Do**: Skip - no actual execution

### ✅ CORRECT: Reporting Actual Execution
```python
shell = ProcessBuilder(cmd)
shell.start()  # Actually executed!
```
**Report**: "Command Injection via ProcessBuilder.start()"

### ❌ WRONG: Reporting Unused Parameter
```java
public void process(String input) {
    String sanitized = sanitize(input);  // Sanitized but not used
    executeQuery("SELECT * FROM users");  // No data flow
}
```
**Don't report**: "SQL Injection"
**Do**: Skip - no data flow from input to sink

### ✅ CORRECT: Reporting Actual Data Flow
```java
public void process(String input) {
    String sanitized = sanitize(input);  // Has sanitization
    if (isBypass(sanitized)) {
        executeQuery("SELECT * FROM users WHERE name = '" + input + "'");  // Raw input!
    }
}
```
**Report**: "SQL Injection - sanitization bypass, raw input reaches query"

### ❌ WRONG: Reporting JSON Response as XSS
```javascript
app.get('/api/user', (req, res) => {
    res.json({ name: req.query.name });  // JSON response, not HTML
});
```
**Don't report**: "XSS"
**Do**: Skip - JSON responses don't execute HTML

### ✅ CORRECT: Reporting HTML Rendering as XSS
```javascript
app.get('/user', (req, res) => {
    res.send('<div>Welcome ' + req.query.name + '</div>');  // HTML rendering!
});
```
**Report**: "XSS - user input rendered in HTML without escaping"

### ❌ WRONG: Reporting Safe String Operation
```python
def handle(filename):
    return f"Processing: {filename}"  # Only string formatting
```
**Don't report**: "Path Traversal"
**Do**: Skip - no file operation

### ✅ CORRECT: Reporting Actual File Operation
```python
def handle(filename):
    return open(filename).read()  # Actual file read!
```
**Report**: "Path Traversal - user input reaches file read operation"
"""


# =============================================================================
# FEW-SHOT EXAMPLES FOR CONFIDENCE CALIBRATION
# =============================================================================

CONFIDENCE_EXAMPLES = """
## Confidence Calibration Examples

### High Confidence (0.9-1.0) - Requires PoC
```python
# Exploitability: Confirmed
# Evidence: Working PoC exists
# Confidence: 0.95
def eval_code(code):
    return eval(code)  # Direct eval with user input
```

### Medium-High Confidence (0.7-0.9) - Clear Data Flow
```python
# Exploitability: Likely
# Evidence: Clear data flow to dangerous function
# Confidence: 0.8
def query(id):
    return execute(f"SELECT * FROM users WHERE id = {id}")
```

### Medium Confidence (0.5-0.7) - Uncertain Sanitization
```python
# Exploitability: Possible
# Evidence: Dangerous pattern but sanitization unclear
# Confidence: 0.6
def query(id):
    clean = sanitize(id)  # Is sanitization effective?
    return execute(f"SELECT * FROM users WHERE id = {clean}")
```

### Low Confidence (0.3-0.5) - Suspicious Only
```python
# Exploitability: Unlikely
# Evidence: Dangerous keyword but no clear attack path
# Confidence: 0.4
# Category: suspicious_code
def get_config(key):
    return CONFIG.get(key)  # User-controlled key?
```
"""


# =============================================================================
# PROMPT BUILDING FUNCTION
# =============================================================================

def build_enhanced_system_prompt(
    base_prompt: str,
    language: str | None = None,
) -> str:
    """
    Build enhanced system prompt with anti-hallucination rules.

    Args:
        base_prompt: Original system prompt.
        language: Programming language being analyzed.

    Returns:
        Enhanced system prompt string.
    """
    enhanced = f"""{base_prompt}

{ANTI_HALLUCINATION_RULES}

{EXECUTION_EVIDENCE_REQUIREMENTS}

{FEW_SHOT_EXAMPLES}

{CONFIDENCE_EXAMPLES}

## Final Reminder
Your primary directive: **Quality over quantity**.
- A missed vulnerability is better than a false positive.
- Only report when you have CONFIRMED evidence.
- When uncertain, use the suspicious_code category.
"""

    return enhanced


def get_anti_hallucination_rules() -> str:
    """Get anti-hallucination rules as a string."""
    return ANTI_HALLUCINATION_RULES


def get_execution_evidence_requirements() -> str:
    """Get execution evidence requirements as a string."""
    return EXECUTION_EVIDENCE_REQUIREMENTS


def get_few_shot_examples() -> str:
    """Get few-shot examples as a string."""
    return FEW_SHOT_EXAMPLES
