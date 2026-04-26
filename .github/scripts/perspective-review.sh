#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Multi-perspective PR review using GitHub Models API.
# Called by the perspective-review.yml workflow.
#
# Usage: perspective-review.sh <repo> <pr_number>
# Requires: GITHUB_TOKEN env var, jq, gh CLI

set -euo pipefail

REPO="$1"
PR_NUMBER="$2"

echo "=== Perspective Review for ${REPO}#${PR_NUMBER} ==="

# Step 1: Get changed files
echo "Fetching changed files..."
gh api "repos/${REPO}/pulls/${PR_NUMBER}/files" \
  --jq '.[].filename' > /tmp/changed_files.txt
echo "Changed files: $(wc -l < /tmp/changed_files.txt)"

# Step 2: Get the diff (truncate to ~60KB for token limits)
echo "Fetching diff..."
gh api "repos/${REPO}/pulls/${PR_NUMBER}" \
  -H "Accept: application/vnd.github.v3.diff" \
  | head -c 60000 > /tmp/pr_diff.txt
echo "Diff size: $(wc -c < /tmp/pr_diff.txt) bytes"

# Step 3: Select perspectives based on changed paths
PERSPECTIVES="reliability-engineer,test-engineer"

if grep -qE 'src/builtins/' /tmp/changed_files.txt 2>/dev/null; then
  PERSPECTIVES="${PERSPECTIVES},semantics-expert,red-teamer"
fi
if grep -qE 'src/(value|number)' /tmp/changed_files.txt 2>/dev/null; then
  PERSPECTIVES="${PERSPECTIVES},semantics-expert"
fi
if grep -qE 'bindings/|src/.*ffi' /tmp/changed_files.txt 2>/dev/null; then
  PERSPECTIVES="${PERSPECTIVES},architect,api-steward"
fi
if grep -qE 'Cargo\.(toml|lock)' /tmp/changed_files.txt 2>/dev/null; then
  PERSPECTIVES="${PERSPECTIVES},security-auditor,architect"
fi
if grep -qE 'src/(interpreter|rvm|compiler|scheduler)' /tmp/changed_files.txt 2>/dev/null; then
  PERSPECTIVES="${PERSPECTIVES},semantics-expert,performance-engineer"
fi

# Deduplicate
PERSPECTIVES=$(echo "$PERSPECTIVES" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
echo "Selected perspectives: ${PERSPECTIVES}"

# Step 4: Build context
echo "Building context..."
KNOWLEDGE_CTX=""
for f in builtin-system value-semantics policy-evaluation-security ffi-boundary; do
  kf="docs/knowledge/${f}.md"
  if [ -f "$kf" ]; then
    KNOWLEDGE_CTX="${KNOWLEDGE_CTX}
--- ${f}.md ---
$(head -c 4000 "$kf")
"
  fi
done

DIFF_CONTENT=$(cat /tmp/pr_diff.txt)

# Step 5: Run each perspective
ALL_FINDINGS=""

for perspective in $(echo "$PERSPECTIVES" | tr ',' ' '); do
  echo "--- Reviewing: ${perspective} ---"

  # Load agent instructions
  AGENT_INSTRUCTIONS=""
  agent_file=".github/agents/${perspective}.agent.md"
  if [ -f "$agent_file" ]; then
    AGENT_INSTRUCTIONS=$(head -c 4000 "$agent_file")
  fi

  # Format display name
  DISPLAY_NAME=$(echo "$perspective" | sed 's/-/ /g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)}1')

  # Build prompt as a temp file to avoid heredoc/quoting issues
  cat > /tmp/review_prompt.txt <<EOF
You are reviewing a pull request from the perspective of a ${DISPLAY_NAME}.

Your agent instructions:
${AGENT_INSTRUCTIONS}

Relevant knowledge context:
${KNOWLEDGE_CTX}

PR Diff:
${DIFF_CONTENT}

Respond with a JSON array of findings. Each finding must have these fields:
- "severity": one of "critical", "important", "suggestion"
- "summary": a single sentence suitable as a GitHub issue title
- "file": the file path (from the diff)
- "line": approximate line number (from the diff), or null
- "explanation": 2-4 sentences explaining the issue

If you find no issues from this perspective, return an empty array: []

Return ONLY valid JSON — no markdown fences, no extra text.
EOF

  PROMPT_CONTENT=$(cat /tmp/review_prompt.txt)

  # Call GitHub Models API using jq for safe JSON encoding
  RESPONSE=$(jq -n \
    --arg model "openai/gpt-4o-mini" \
    --arg prompt "$PROMPT_CONTENT" \
    '{
      model: $model,
      messages: [
        {role: "system", content: "You are a code reviewer. Return findings as a JSON array only."},
        {role: "user", content: $prompt}
      ],
      temperature: 0.1
    }' | curl -s -X POST "https://models.github.ai/inference/chat/completions" \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "Content-Type: application/json" \
      -d @- 2>/dev/null || echo '{"error": "API call failed"}')

  # Extract content
  CONTENT=$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)

  if [ -z "$CONTENT" ]; then
    ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error // .message // "Unknown error"' 2>/dev/null || echo "Unknown error")
    echo "  API error: ${ERROR_MSG}"
    continue
  fi

  # Try to parse as JSON array and render as tagged markdown
  RENDERED=$(echo "$CONTENT" | jq -r --arg perspective "$DISPLAY_NAME" '
    if type == "array" then
      .[] |
      "**[\($perspective)]** " +
      (if .severity == "critical" then "🔴 critical" elif .severity == "important" then "🟠 important" else "🔵 suggestion" end) +
      "\n> " + .summary + "\n\n" + .explanation +
      (if .file then "\n\n📁 `" + .file + "`" + (if .line then ":" + (.line | tostring) else "" end) else "" end) +
      "\n\n---\n"
    else
      empty
    end
  ' 2>/dev/null || true)

  if [ -n "$RENDERED" ]; then
    FINDING_COUNT=$(echo "$CONTENT" | jq 'if type == "array" then length else 0 end' 2>/dev/null || echo 0)
    echo "  Found ${FINDING_COUNT} findings"
    ALL_FINDINGS="${ALL_FINDINGS}${RENDERED}"
  else
    echo "  No findings (or unparseable response)"
  fi
done

# Step 6: Build the final comment
MARKER="<!-- perspective-review-bot -->"

if [ -n "$ALL_FINDINGS" ]; then
  cat > /tmp/review_comment.md <<EOF
${MARKER}
## 🔍 Perspective Review

Automated multi-perspective review of this PR.
Each finding is tagged with the perspective that identified it.

---

$(echo -e "$ALL_FINDINGS")

<sub>Generated by perspective-review workflow • Perspectives: ${PERSPECTIVES}</sub>
EOF
else
  cat > /tmp/review_comment.md <<EOF
${MARKER}
## 🔍 Perspective Review

✅ No significant findings from the selected perspectives.

<sub>Generated by perspective-review workflow • Perspectives: ${PERSPECTIVES}</sub>
EOF
fi

# Step 7: Upsert the comment (update existing or create new)
echo "Posting review comment..."
EXISTING_ID=$(gh api "repos/${REPO}/issues/${PR_NUMBER}/comments" \
  --jq ".[] | select(.body | contains(\"${MARKER}\")) | .id" \
  | head -1 || true)

COMMENT_BODY=$(cat /tmp/review_comment.md)

if [ -n "$EXISTING_ID" ]; then
  gh api "repos/${REPO}/issues/comments/${EXISTING_ID}" \
    -X PATCH \
    -f body="$COMMENT_BODY"
  echo "Updated existing comment ${EXISTING_ID}"
else
  gh api "repos/${REPO}/issues/${PR_NUMBER}/comments" \
    -f body="$COMMENT_BODY"
  echo "Created new review comment"
fi

echo "=== Review complete ==="
