# OPA Rego Placeholder — Tool Policy
# Future: serve via OPA sidecar for policy-as-code evaluation
# Currently the LocalPolicyEngine provides equivalent logic in Python

package securezeph.tool_policy

default allow = false

# Allow tools from the explicit allowlist
allow {
    input.tool_name == data.allowed_tools[_].name
}

# Deny tools from the explicit blocklist
deny {
    input.tool_name == data.blocked_tools[_].name
}

# Deny if chain depth exceeded
deny {
    input.chain_depth > data.global_limits.max_chain_depth
}

# Require approval for high-risk actions
require_approval {
    input.risk_score > data.risk_thresholds.require_approval_above
    not bypass_tool
}

bypass_tool {
    input.tool_name == data.bypass_tools[_]
}
