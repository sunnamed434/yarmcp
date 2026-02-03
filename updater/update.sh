#!/bin/bash
set -e

CONFIG_PATH="${CONFIG_PATH:-/opt/yarmcp/config/repos.yaml}"
REPOS_PATH="${REPOS_PATH:-/opt/yarmcp/repos}"

log() {
    echo "[$(date -Iseconds)] $1"
}

error() {
    echo "[$(date -Iseconds)] ERROR: $1" >&2
}

# Configure git credentials for private repos (if GITHUB_TOKEN is set)
if [ -n "$GITHUB_TOKEN" ]; then
    log "Configuring GitHub authentication..."
    git config --global credential.helper store
    echo "https://x-access-token:${GITHUB_TOKEN}@github.com" > ~/.git-credentials
    chmod 600 ~/.git-credentials
fi

# Check if config file exists
if [ ! -f "$CONFIG_PATH" ]; then
    error "Config file not found: $CONFIG_PATH"
    exit 1
fi

# Create repos directory if it doesn't exist
mkdir -p "$REPOS_PATH"

# Read repos from config using yq
REPOS_COUNT=$(yq eval '.repos | length' "$CONFIG_PATH")

if [ "$REPOS_COUNT" -eq 0 ]; then
    log "No repositories configured"
    exit 0
fi

log "Starting repository sync..."

SUCCESS_COUNT=0
FAIL_COUNT=0

for i in $(seq 0 $((REPOS_COUNT - 1))); do
    # Parse repo config using yq
    NAME=$(yq eval ".repos[$i].name" "$CONFIG_PATH")
    URL=$(yq eval ".repos[$i].url" "$CONFIG_PATH")
    BRANCH=$(yq eval ".repos[$i].branch // \"\"" "$CONFIG_PATH")
    AUTO_UPDATE=$(yq eval ".repos[$i].auto_update // true" "$CONFIG_PATH")

    # Skip if auto_update is false
    if [ "$AUTO_UPDATE" = "false" ]; then
        log "Skipping $NAME (auto_update disabled)"
        continue
    fi

    REPO_DIR="$REPOS_PATH/$NAME"

    if [ -d "$REPO_DIR/.git" ]; then
        # Repository exists, pull updates
        log "Updating $NAME..."
        cd "$REPO_DIR"

        # Determine which branch to update
        UPDATE_BRANCH="$BRANCH"
        if [ -z "$UPDATE_BRANCH" ] || [ "$UPDATE_BRANCH" = "null" ]; then
            # No branch specified, use current branch
            UPDATE_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
            log "Using current branch: $UPDATE_BRANCH"
        fi

        # Fetch and reset to remote branch (clean pull)
        FETCH_OUTPUT=$(git fetch --depth=1 origin "$UPDATE_BRANCH" 2>&1)
        FETCH_EXIT=$?

        if [ $FETCH_EXIT -eq 0 ]; then
            RESET_OUTPUT=$(git reset --hard "origin/$UPDATE_BRANCH" 2>&1)
            RESET_EXIT=$?

            if [ $RESET_EXIT -eq 0 ]; then
                log "Updated $NAME successfully"
                ((SUCCESS_COUNT++)) || true
            else
                error "Failed to reset $NAME to origin/$UPDATE_BRANCH (exit code: $RESET_EXIT)"
                error "Git reset output: $RESET_OUTPUT"
                ((FAIL_COUNT++)) || true
            fi
        else
            error "Failed to fetch updates for $NAME (exit code: $FETCH_EXIT)"
            error "Git fetch output: $FETCH_OUTPUT"
            error "Branch: $UPDATE_BRANCH"
            ((FAIL_COUNT++)) || true
        fi
    else
        # Repository doesn't exist, clone it
        log "Cloning $NAME from $URL..."

        # If branch is specified, verify it exists
        if [ -n "$BRANCH" ] && [ "$BRANCH" != "null" ]; then
            log "Checking if branch '$BRANCH' exists..."
            if ! git ls-remote --heads "$URL" "refs/heads/$BRANCH" 2>/dev/null | grep -q "refs/heads/$BRANCH"; then
                error "Branch '$BRANCH' not found in $NAME"
                error "Make sure the branch exists in the repository."

                # Try to list available branches (with timeout to avoid slowness)
                BRANCHES=$(timeout 5s git ls-remote --heads "$URL" 2>/dev/null | awk '{print $2}' | sed 's|refs/heads/||' | head -10)
                if [ -n "$BRANCHES" ]; then
                    error "Available branches (showing first 10):"
                    echo "$BRANCHES" | while read -r b; do
                        error "  - $b"
                    done
                fi

                ((FAIL_COUNT++)) || true
                continue
            fi

            # SECURITY: Never use recursive clone (CVE-2025-48384)
            CLONE_OUTPUT=$(git clone --depth=1 --branch "$BRANCH" --no-recurse-submodules "$URL" "$REPO_DIR" 2>&1)
            CLONE_EXIT=$?

            if [ $CLONE_EXIT -eq 0 ]; then
                log "Cloned $NAME successfully"
                ((SUCCESS_COUNT++)) || true
            else
                error "Failed to clone $NAME (exit code: $CLONE_EXIT)"
                error "Git clone output: $CLONE_OUTPUT"
                error "URL: $URL, Branch: $BRANCH"
                ((FAIL_COUNT++)) || true
            fi
        else
            # No branch specified, use repository default
            log "Using default branch..."

            # SECURITY: Never use recursive clone (CVE-2025-48384)
            CLONE_OUTPUT=$(git clone --depth=1 --no-recurse-submodules "$URL" "$REPO_DIR" 2>&1)
            CLONE_EXIT=$?

            if [ $CLONE_EXIT -eq 0 ]; then
                log "Cloned $NAME successfully"
                ((SUCCESS_COUNT++)) || true
            else
                error "Failed to clone $NAME (exit code: $CLONE_EXIT)"
                error "Git clone output: $CLONE_OUTPUT"
                error "URL: $URL"
                ((FAIL_COUNT++)) || true
            fi
        fi
    fi
done

log "Sync complete: $SUCCESS_COUNT succeeded, $FAIL_COUNT failed"

# Exit with error if all repos failed
if [ "$SUCCESS_COUNT" -eq 0 ] && [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi

exit 0
