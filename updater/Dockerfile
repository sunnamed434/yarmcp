FROM alpine:3.23

# Install git and dependencies
RUN apk add --no-cache \
    git \
    openssh-client \
    bash \
    yq \
    curl

# Install supercronic for container-friendly cron
ENV SUPERCRONIC_URL=https://github.com/aptible/supercronic/releases/download/v0.2.29/supercronic-linux-amd64 \
    SUPERCRONIC_SHA1SUM=cd48d45c4b10f3f0bfdd3a57d054cd05ac96812b

RUN curl -fsSLO "$SUPERCRONIC_URL" \
    && echo "${SUPERCRONIC_SHA1SUM}  supercronic-linux-amd64" | sha1sum -c - \
    && chmod +x supercronic-linux-amd64 \
    && mv supercronic-linux-amd64 /usr/local/bin/supercronic

WORKDIR /app

# Copy scripts
COPY update.sh /app/update.sh
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/*.sh

# Create non-root user
RUN adduser -D -u 1000 updater

# Git safety configuration
RUN git config --global core.hooksPath /dev/null \
    && git config --global advice.detachedHead false \
    && git config --global init.defaultBranch main

# Default schedule: every 6 hours
ENV UPDATE_SCHEDULE="0 */6 * * *"
ENV REPOS_PATH="/opt/yarmcp/repos"
ENV CONFIG_PATH="/opt/yarmcp/config/repos.yaml"

# Switch to non-root user for security
USER updater

ENTRYPOINT ["/app/entrypoint.sh"]
