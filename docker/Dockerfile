# armor dev image
# Extends the shared Claude Code base with the Python toolchain.
# Python 3.12 + pip + build-essential are already in the base image — no extra runtime install needed.
FROM claude-project-dev:latest

# Align container uid/gid to host so bind-mounted host files are accessible.
RUN usermod -u 1000 developer \
 && groupmod -g 1000 developer \
 && chown -R developer:developer /app /home/developer
