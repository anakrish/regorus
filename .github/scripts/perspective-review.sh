#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Multi-perspective PR review using GitHub Models API.
# Posts one PR review per perspective with inline code comments.
#
# Usage: perspective-review.sh <repo> <pr_number>
# Requires: GITHUB_TOKEN env var, jq, gh CLI

set -euo pipefail

REPO="$1"
PR_NUMBER="$2"

echo "=== Perspective Review for ${REPO}#${PR_NUMBER} ==="

# Step 1: Get PR metadata (head SHA) and changed files
echo "Fetching PR metadata..."
PR_DATA=$(gh api "repos/${REPO}/pulls/${PR_NUMBER}")
HEAD_SHA=$(echo "$PR_DATA" | jq -r '.head.sha')
echo "Head SHA: ${HEAD_SHA}"

echo "Fetching changed files..."
gh api "repos/${REPO}/pulls/${PR_NUMBER}/files" --paginate \
  --jq '.[].filename' > /tmp/changed_files.txt
echo "Changed files: $(wc -l < /tmp/changed_files.txt)"

# Step 2: Get the diff and extract valid line anchors
echo "Fetching diff..."
gh api "repos/${REPO}/pulls/${PR_NUMBER}" \
  -H "Accept: application/vnd.github.v3.diff" \
  | head -c 60000 > /tmp/pr_diff.txt
echo "Diff size: $(wc -c < /tmp/pr_diff.txt) bytes"

# Parse diff to extract valid RIGHT-side line anchors with code content.
# Format: file:line:type:code  (type is "added" for + lines, "context" for unchanged)
echo "Extracting valid line anchors from diff..."
awk '
  /^diff --git/ { file = "" }
  /^\+\+\+ b\// { file = substr($0, 7) }
  /^@@ / {
    match($0, /\+([0-9]+)(,([0-9]+))?/, arr)
    start = arr[1] + 0
    line = start
  }
  file != "" && !/^diff --git/ && !/^---/ && !/^\+\+\+/ && !/^@@/ {
    if (/^-/) {
      # Deleted line: skip (not on RIGHT side)
    } else if (/^\+/) {
      # Added line
      code = substr($0, 2)  # strip leading +
      gsub(/\t/, "    ", code)
      print file ":" line ":added:" code
      line++
    } else {
      # Context line
      code = substr($0, 2)  # strip leading space
      gsub(/\t/, "    ", code)
      print file ":" line ":context:" code
      line++
    }
  }
' /tmp/pr_diff.txt > /tmp/valid_anchors_full.txt

# Also create a plain file:line list for validation
awk -F: '{print $1 ":" $2}' /tmp/valid_anchors_full.txt > /tmp/valid_anchors.txt

ADDED_COUNT=$(grep -c ':added:' /tmp/valid_anchors_full.txt || echo 0)
CONTEXT_COUNT=$(grep -c ':context:' /tmp/valid_anchors_full.txt || echo 0)
echo "Valid anchors: ${ADDED_COUNT} added, ${CONTEXT_COUNT} context"

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

# Step 4: Build context from knowledge files
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

# Build a structured anchor table for the prompt.
# Show added lines prominently, include some context lines for reference.
ANCHOR_TABLE=$(awk -F: '
  {
    file = $1; line = $2; type = $3
    # Rejoin remaining fields as code (code may contain colons)
    code = ""
    for (i = 4; i <= NF; i++) {
      if (i > 4) code = code ":"
      code = code $i
    }
    if (type == "added") {
      printf "  + %s:%s  %s\n", file, line, code
    }
  }
' /tmp/valid_anchors_full.txt)

# Also list context lines but more compactly (just file:line ranges)
CONTEXT_SUMMARY=$(awk -F: '
  $3 == "context" { print $1 ":" $2 }
' /tmp/valid_anchors_full.txt | head -50)

# Plain file:line list for validation
VALID_ANCHORS_PLAIN=$(cat /tmp/valid_anchors.txt)

# Step 5: Review with each perspective, posting one PR review per perspective
TOTAL_FINDINGS=0

for perspective in $(echo "$PERSPECTIVES" | tr ',' ' '); do
  echo "--- Reviewing: ${perspective} ---"

  # Load agent instructions
  AGENT_INSTRUCTIONS=""
  agent_file=".github/agents/${perspective}.agent.md"
  if [ -f "$agent_file" ]; then
    AGENT_INSTRUCTIONS=$(head -c 4000 "$agent_file")
  fi

  # Format display name and emoji
  DISPLAY_NAME=$(echo "$perspective" | sed 's/-/ /g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)}1')
  case "$perspective" in
    red-teamer)              EMOJI="🔴" ;;
    security-auditor)        EMOJI="🔒" ;;
    reliability-engineer)    EMOJI="⚙️" ;;
    test-engineer)           EMOJI="🧪" ;;
    semantics-expert)        EMOJI="📐" ;;
    performance-engineer)    EMOJI="⚡" ;;
    architect)               EMOJI="🏗️" ;;
    api-steward)             EMOJI="📡" ;;
    *)                       EMOJI="🔍" ;;
  esac

  cat > /tmp/review_prompt.txt <<PROMPT
You are reviewing a pull request from the perspective of a ${DISPLAY_NAME}.

Your agent instructions:
${AGENT_INSTRUCTIONS}

Relevant knowledge context:
${KNOWLEDGE_CTX}

PR Diff:
${DIFF_CONTENT}

=== ANCHORING INSTRUCTIONS ===

Each finding MUST be anchored to a specific line in the diff.
Below are the ADDED lines (marked with +) that you can reference.
Pick the most relevant added line for each finding.

ADDED LINES (preferred — use these):
${ANCHOR_TABLE}

CONTEXT LINES (also valid, but prefer added lines above):
${CONTEXT_SUMMARY}

For each finding, set "file" and "line" to an EXACT file:line pair from the lists above.
Do NOT invent line numbers. Do NOT use line numbers that aren't listed.

=== OUTPUT FORMAT ===

Respond with a JSON array. Each finding:
- "severity": "critical" | "important" | "suggestion"
- "title": one-sentence heading
- "file": exact file path from the anchor lists
- "line": exact line number from the anchor lists
- "body": 2-4 sentence explanation in markdown

If no issues found, return: []
Return ONLY valid JSON — no markdown fences, no commentary.
PROMPT

  PROMPT_CONTENT=$(cat /tmp/review_prompt.txt)

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

  CONTENT=$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)

  if [ -z "$CONTENT" ]; then
    ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error // .message // "Unknown error"' 2>/dev/null || echo "Unknown error")
    echo "  API error: ${ERROR_MSG}"
    continue
  fi

  # Strip markdown fences if the model wrapped them
  CONTENT=$(echo "$CONTENT" | sed 's/^```json//; s/^```//; /^$/d')

  # Validate JSON
  if ! echo "$CONTENT" | jq empty 2>/dev/null; then
    echo "  Invalid JSON response, skipping"
    continue
  fi

  FINDING_COUNT=$(echo "$CONTENT" | jq 'if type == "array" then length else 0 end' 2>/dev/null || echo 0)

  if [ "$FINDING_COUNT" -eq 0 ]; then
    echo "  No findings"
    continue
  fi

  echo "  Found ${FINDING_COUNT} findings"
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + FINDING_COUNT))

  # Separate findings into anchored (inline) and unanchored (body-only)
  # Validate each finding's file:line against the valid anchors list
  INLINE_COMMENTS=$(echo "$CONTENT" | jq -c --arg anchors "$VALID_ANCHORS_PLAIN" '
    ($anchors | split("\n") | map(select(. != ""))) as $valid |
    [.[] | select(.file != null and .line != null) |
      select((.file + ":" + (.line | tostring)) as $key | $valid | any(. == $key))]
  ' 2>/dev/null || echo "[]")

  UNANCHORED=$(echo "$CONTENT" | jq -c --arg anchors "$VALID_ANCHORS_PLAIN" '
    ($anchors | split("\n") | map(select(. != ""))) as $valid |
    [.[] | select(
      .file == null or .line == null or
      ((.file + ":" + (.line | tostring)) as $key | $valid | all(. != $key))
    )]
  ' 2>/dev/null || echo "[]")

  INLINE_COUNT=$(echo "$INLINE_COMMENTS" | jq 'length' 2>/dev/null || echo 0)
  UNANCHORED_COUNT=$(echo "$UNANCHORED" | jq 'length' 2>/dev/null || echo 0)
  echo "  Inline: ${INLINE_COUNT}, Unanchored: ${UNANCHORED_COUNT}"

  # Build review body
  SEVERITY_ICON() {
    case "$1" in
      critical)   echo "🔴" ;;
      important)  echo "🟠" ;;
      suggestion) echo "🔵" ;;
      *)          echo "⚪" ;;
    esac
  }

  REVIEW_BODY="${EMOJI} **${DISPLAY_NAME}** — ${FINDING_COUNT} finding(s)"

  # Add unanchored findings to the review body
  if [ "$UNANCHORED_COUNT" -gt 0 ]; then
    UNANCHORED_TEXT=$(echo "$UNANCHORED" | jq -r '
      .[] |
      "\n\n" +
      (if .severity == "critical" then "🔴" elif .severity == "important" then "🟠" else "🔵" end) +
      " **" + .severity + "**: " + .title +
      "\n" + .body +
      (if .file then "\n📁 `" + .file + "`" + (if .line then ":" + (.line | tostring) else "" end) else "" end)
    ' 2>/dev/null || true)
    REVIEW_BODY="${REVIEW_BODY}

### General findings
${UNANCHORED_TEXT}"
  fi

  # Build inline comments JSON for the PR Review API
  COMMENTS_JSON="[]"
  if [ "$INLINE_COUNT" -gt 0 ]; then
    COMMENTS_JSON=$(echo "$INLINE_COMMENTS" | jq -c --arg perspective "$DISPLAY_NAME" '
      [.[] | {
        path: .file,
        line: .line,
        side: "RIGHT",
        body: (
          "**" +
          (if .severity == "critical" then "🔴 Critical" elif .severity == "important" then "🟠 Important" else "🔵 Suggestion" end) +
          "**: " + .title + "\n\n" + .body
        )
      }]
    ' 2>/dev/null || echo "[]")
  fi

  # Post the PR review
  echo "  Posting review..."
  REVIEW_PAYLOAD=$(jq -n \
    --arg sha "$HEAD_SHA" \
    --arg body "$REVIEW_BODY" \
    --argjson comments "$COMMENTS_JSON" \
    '{
      commit_id: $sha,
      body: $body,
      event: "COMMENT",
      comments: $comments
    }')

  REVIEW_RESULT=$(echo "$REVIEW_PAYLOAD" | gh api "repos/${REPO}/pulls/${PR_NUMBER}/reviews" \
    --input - 2>&1 || true)

  if echo "$REVIEW_RESULT" | jq -e '.id' > /dev/null 2>&1; then
    REVIEW_ID=$(echo "$REVIEW_RESULT" | jq -r '.id')
    echo "  Posted review ${REVIEW_ID}"
  else
    # If inline comments failed (invalid anchors), retry without them
    echo "  Review with inline comments failed, retrying as body-only..."
    REVIEW_BODY="${REVIEW_BODY}

### Findings"
    BODY_FINDINGS=$(echo "$CONTENT" | jq -r '
      .[] |
      "\n" +
      (if .severity == "critical" then "🔴" elif .severity == "important" then "🟠" else "🔵" end) +
      " **" + .severity + "**: " + .title +
      "\n" + .body +
      (if .file then "\n📁 `" + .file + "`" + (if .line then ":" + (.line | tostring) else "" end) else "" end)
    ' 2>/dev/null || true)
    REVIEW_BODY="${REVIEW_BODY}${BODY_FINDINGS}"

    jq -n \
      --arg sha "$HEAD_SHA" \
      --arg body "$REVIEW_BODY" \
      '{commit_id: $sha, body: $body, event: "COMMENT", comments: []}' \
    | gh api "repos/${REPO}/pulls/${PR_NUMBER}/reviews" --input - > /dev/null 2>&1 \
    && echo "  Posted body-only review" \
    || echo "  Failed to post review"
  fi
done

echo "=== Review complete: ${TOTAL_FINDINGS} total findings ==="
