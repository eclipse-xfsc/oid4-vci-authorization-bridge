#!/usr/bin/env bash
set -Eeuo pipefail

NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
BRIDGE_URL="${BRIDGE_URL:-http://127.0.0.1:8081}"
TENANT_ID="${TENANT_ID:-tenant_space}"
GROUP_ID="${GROUP_ID:-signer}"
NONCE="${NONCE:-integration-test-nonce}"
TIMEOUT="${TIMEOUT:-10s}"

GENERATE_TOPIC="auth.authorization.generate"
GENERATE_TYPE="auth.authorization.generate"

VALIDATE_TOPIC="auth.authorization.validate"
VALIDATE_TYPE="auth.authorization.validate.v1"

SOURCE="authorization-bridge-cli-test"

for cmd in nats jq curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 1
  fi
done

uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
  else
    printf '%s-%s-%s\n' "$(date +%s)" "$$" "$RANDOM"
  fi
}

# The XFSC cloud-event-provider expects the NATS message body to contain a
# complete CloudEvent. Sending only the business payload causes:
#
#   specversion: no specversion
#
# Therefore we use CloudEvents structured JSON mode here.
nats_cloudevent_request() {
  local subject="$1"
  local event_type="$2"
  local data_json="$3"
  local event_id
  local event_json

  event_id="$(uuid)"

  event_json="$(jq -nc \
    --arg specversion "1.0" \
    --arg id "$event_id" \
    --arg source "$SOURCE" \
    --arg type "$event_type" \
    --arg datacontenttype "application/json" \
    --argjson data "$data_json" \
    '{
      specversion: $specversion,
      id: $id,
      source: $source,
      type: $type,
      datacontenttype: $datacontenttype,
      data: $data
    }')"

  nats --server "$NATS_URL" request "$subject" "$event_json" \
    --raw \
    --timeout "$TIMEOUT"
}

unwrap_cloudevent_data() {
  local event_json="$1"

  if ! jq -e '.specversion and .id and .source and .type and has("data")' \
      >/dev/null <<<"$event_json"; then
    echo "ERROR: NATS response is not a valid structured CloudEvent:" >&2
    echo "$event_json" >&2
    return 1
  fi

  jq -c '.data' <<<"$event_json"
}

echo "==> Checking authorization bridge health"
curl --fail --silent --show-error "$BRIDGE_URL/health" | jq .

echo
echo "==> 1/3 Generate pre-authorized code via NATS CloudEvent"

REQUEST_ID="$(uuid)"

GENERATE_DATA="$(jq -nc \
  --arg tenant "$TENANT_ID" \
  --arg request "$REQUEST_ID" \
  --arg group "$GROUP_ID" \
  --arg nonce "$NONCE" \
  '{
    tenant_id: $tenant,
    request_id: $request,
    group_id: $group,
    twoFactor: {
      enabled: false,
      recipientType: "",
      recipientAddress: ""
    },
    credential_configurations: [],
    nonce: $nonce,
    claims: []
  }')"

GENERATE_EVENT_REPLY="$(
  nats_cloudevent_request \
    "$GENERATE_TOPIC" \
    "$GENERATE_TYPE" \
    "$GENERATE_DATA"
)"

echo "CloudEvent response:"
jq . <<<"$GENERATE_EVENT_REPLY"

GENERATE_REPLY="$(unwrap_cloudevent_data "$GENERATE_EVENT_REPLY")"

echo "Business response:"
jq . <<<"$GENERATE_REPLY"

GENERATE_ERROR="$(jq -r '.error // empty' <<<"$GENERATE_REPLY")"
if [[ -n "$GENERATE_ERROR" && "$GENERATE_ERROR" != "null" ]]; then
  echo "ERROR: generate authorization returned an error: $GENERATE_ERROR" >&2
  exit 1
fi

AUTH_CODE="$(jq -r '.code // empty' <<<"$GENERATE_REPLY")"

if [[ -z "$AUTH_CODE" ]]; then
  echo "ERROR: no pre-authorized code in NATS response" >&2
  exit 1
fi

echo "pre-authorized_code=$AUTH_CODE"

# tx_code is an object in the current messaging model. It describes whether
# and how a transaction code must be entered; it is not itself the user's PIN.
TX_CODE_DESCRIPTION="$(jq -c '.tx_code // empty' <<<"$GENERATE_REPLY")"
if [[ -n "$TX_CODE_DESCRIPTION" ]]; then
  echo "tx_code metadata=$TX_CODE_DESCRIPTION"
fi

echo
echo "==> 2/3 Exchange pre-authorized code for access token"

TOKEN_REPLY="$(
  curl \
    --fail-with-body \
    --silent \
    --show-error \
    --request POST \
    "$BRIDGE_URL/token" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
    --data-urlencode "pre-authorized_code=$AUTH_CODE"
)"

jq . <<<"$TOKEN_REPLY"

ACCESS_TOKEN="$(jq -r '.access_token // empty' <<<"$TOKEN_REPLY")"

if [[ -z "$ACCESS_TOKEN" ]]; then
  echo "ERROR: token endpoint returned no access_token" >&2
  exit 1
fi

echo
echo "==> 3/3 Validate access token via NATS CloudEvent"

VALIDATE_DATA="$(jq -nc \
  --arg tenant "$TENANT_ID" \
  --arg request "$REQUEST_ID" \
  --arg group "$GROUP_ID" \
  --arg token "$ACCESS_TOKEN" \
  '{
    tenant_id: $tenant,
    request_id: $request,
    group_id: $group,
    Params: {
      key: $token
    }
  }')"

VALIDATE_EVENT_REPLY="$(
  nats_cloudevent_request \
    "$VALIDATE_TOPIC" \
    "$VALIDATE_TYPE" \
    "$VALIDATE_DATA"
)"

echo "CloudEvent response:"
jq . <<<"$VALIDATE_EVENT_REPLY"

VALIDATE_REPLY="$(unwrap_cloudevent_data "$VALIDATE_EVENT_REPLY")"

echo "Business response:"
jq . <<<"$VALIDATE_REPLY"

VALID="$(jq -r '.valid // false' <<<"$VALIDATE_REPLY")"

if [[ "$VALID" != "true" ]]; then
  echo "ERROR: access token validation failed" >&2
  exit 1
fi

echo
echo "SUCCESS: full pre-authorization flow completed"
echo "request_id=$REQUEST_ID"
echo "nonce=$(jq -r '.nonce // empty' <<<"$VALIDATE_REPLY")"
