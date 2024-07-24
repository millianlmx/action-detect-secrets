#!/bin/sh

cd "${GITHUB_WORKSPACE}" || exit 1

export REVIEWDOG_GITHUB_API_TOKEN="${INPUT_GITHUB_TOKEN}"

detect-secrets --version

echo "$HUGGINGFACE_TOKEN"

git config --global --add safe.directory /github/workspace

if [ -n "${INPUT_BASELINE_PATH}" ]; then
    # When .secrets.baseline is provided, the file is only updated and not written to stdout
    /usr/local/bin/detect-secrets scan ${INPUT_DETECT_SECRETS_FLAGS} --baseline ${INPUT_BASELINE_PATH} ${INPUT_WORKDIR}
    mv ${INPUT_BASELINE_PATH} /tmp/.secrets.baseline
else
    /usr/local/bin/detect-secrets scan ${INPUT_DETECT_SECRETS_FLAGS} ${INPUT_WORKDIR} > /tmp/.secrets.baseline
    echo "Scan Done"
    ls -al /tmp/
fi

detect-secrets audit /tmp/.secrets.baseline --report > /tmp/.secrets.audit

ls -al /tmp/

if [ "${INPUT_SKIP_AUDITED}" = "true" ]; then
    SKIP_AUDITED_FLAG="--skip-audited"
fi
if [ "${INPUT_VERBOSE}" = "true" ]; then
    VERBOSE_FLAG="--verbose"
fi

cat /tmp/.secrets.baseline | baseline2rdf ${SKIP_AUDITED_FLAG} ${VERBOSE_FLAG}
cat /tmp/.secrets.rdf
cat /tmp/.secrets.rdf | sed -e 's/\x1b\[[0-9;]*m//g' | reviewdog -f=rdjson \
        -name="${INPUT_NAME:-detect-secrets}" \
        -filter-mode="${INPUT_FILTER_MODE:-added}" \
        -reporter="${INPUT_REPORTER:-github-pr-check}" \
        -fail-on-error="${INPUT_FAIL_ON_ERROR}" \
        -level="${INPUT_LEVEL}" \
        ${INPUT_REVIEWDOG_FLAGS}
