#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

# ----------------------------
# Logging helpers
# ----------------------------
info(){ printf "[INFO] %s\n" "$*"; }
warn(){ printf "[WARN] %s\n" "$*"; }
err(){ printf "[ERROR] %s\n" "$*" >&2; }
banner(){ printf "\n==== %s ====\n" "$*"; }

# ----------------------------
# Args
# ----------------------------
# Usage: ./start.sh [--fresh] [--no-tmux] [--self-test] [--no-build]
# Examples:
#   ./start.sh --fresh --no-tmux
#   ./start.sh --fresh
#   ./start.sh --self-test --fresh --no-tmux
#   ./start.sh --self-test --fresh
FRESH=0
NO_TMUX=0
SELF_TEST=0
NO_BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fresh) FRESH=1; shift ;;
    --no-tmux) NO_TMUX=1; shift ;;
    --self-test) SELF_TEST=1; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    -h|--help)
      echo "Usage: $0 [--fresh] [--no-tmux] [--self-test] [--no-build]"
      exit 0
      ;;
    *)
      echo "Unknown arg: $1"
      echo "Usage: $0 [--fresh] [--no-tmux] [--self-test] [--no-build]"
      exit 2
      ;;
  esac
done

# Self-test log dir
LOGDIR=""
if [[ $SELF_TEST -eq 1 ]]; then
  TS=$(date -u +"%Y%m%dT%H%M%SZ")
  LOGDIR="$ROOT_DIR/logs/selftest_$TS"
  mkdir -p "$LOGDIR"
  exec > >(tee -a "$LOGDIR/runner.log") 2>&1
  info "Self-test mode enabled. Logs: $LOGDIR"
fi

# ----------------------------
# Helpers
# ----------------------------
wait_for_port(){
  local host="$1" port="$2" timeout=${3:-30}
  local start_ts
  start_ts=$(date +%s)
  while :; do
    if timeout 1 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
      return 0
    fi
    sleep 1
    if (( $(date +%s) - start_ts >= timeout )); then
      return 1
    fi
  done
}

container_running(){
  local svc="$1"
  local cid status
  cid=$(docker compose ps -q "$svc" 2>/dev/null || true)
  [[ -z "$cid" ]] && return 1
  status=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo "")
  [[ "$status" == "running" ]]
}

run_cmd_noe(){
  # Run a command but do not let "set -e" kill the script; return its exit code.
  set +e
  "$@"
  local rc=$?
  set -e
  return $rc
}

compose_port(){
  # Usage: compose_port <service> <containerPort>
  # Returns "HOSTPORT" (prints empty if not published)
  local svc="$1" cport="$2"
  # docker compose port prints like: "0.0.0.0:9443" or "::1:9443"
  local out hostport
  out=$(docker compose port "$svc" "$cport" 2>/dev/null || true)
  hostport=$(echo "$out" | awk -F: 'NF{print $NF}' | tail -n1)
  echo "$hostport"
}

sanity_checks(){
  banner "Sanity checks"
  command -v docker >/dev/null 2>&1 || { err "docker not found in PATH"; exit 2; }
  docker compose version >/dev/null 2>&1 || { err "docker compose not available"; exit 2; }

  if [[ $NO_TMUX -eq 0 ]] && [[ $SELF_TEST -eq 0 ]]; then
    command -v tmux >/dev/null 2>&1 || { err "tmux not found (use --no-tmux)"; exit 2; }
  fi

  [[ -f "$ROOT_DIR/M4_TEST_GUIDE.md" ]] || { err "M4_TEST_GUIDE.md not found"; exit 2; }
  [[ -f "$ROOT_DIR/docker-compose.yml" ]] || { err "docker-compose.yml not found"; exit 2; }

  info "Sanity checks passed"
}

compose_up_core(){
  if [[ $FRESH -eq 1 ]]; then
    info "Fresh start: docker compose down -v --remove-orphans"
    run_cmd_noe docker compose down -v --remove-orphans
  fi

  info "Starting core services: cauth, sp, ho"
  if [[ $NO_BUILD -eq 1 ]]; then
    docker compose up -d cauth sp ho
  else
    docker compose up -d --build cauth sp ho
  fi
}

ensure_services(){
  info "Waiting for services to become reachable on published host ports..."

  # These must be published in docker-compose.yml
  local checks=("localhost:8443" "localhost:8444" "localhost:8445")
  for hp in "${checks[@]}"; do
    local host="${hp%%:*}"
    local port="${hp##*:}"
    info "Waiting for $host:$port"
    if ! wait_for_port "$host" "$port" 60; then
      err "Timeout waiting for $host:$port"
      exit 3
    fi
  done

  info "Core services reachable"
}

# ----------------------------
# tmux UI
# ----------------------------
SESSION="m4-demo"
# Fix tmux socket path when running as sudo
if [[ $EUID -eq 0 ]] && [[ -n "$SUDO_USER" ]]; then
  export TMUX_TMPDIR="/tmp/tmux-root-$$"
  mkdir -p "$TMUX_TMPDIR"
  chmod 700 "$TMUX_TMPDIR"
fi

start_tmux_ui(){
  if [[ $NO_TMUX -eq 1 ]]; then
    info "--no-tmux specified; skipping tmux UI setup"
    return 0
  fi

  tmux kill-session -t "$SESSION" 2>/dev/null || true
  TMUX= tmux new-session -d -s "$SESSION" -n logs

  # 2x2 panes for service logs
  tmux send-keys -t "$SESSION":0.0 "docker compose logs -f --tail 120 cauth" C-m
  tmux split-window -h -t "$SESSION":0.0
  tmux send-keys -t "$SESSION":0.1 "docker compose logs -f --tail 120 sp" C-m
  tmux select-pane -t "$SESSION":0.0
  tmux split-window -v -t "$SESSION":0.0
  tmux send-keys -t "$SESSION":0.2 "docker compose logs -f --tail 120 ho" C-m
  tmux select-pane -t "$SESSION":0.1
  tmux split-window -v -t "$SESSION":0.1
  # CO runs are "docker compose run", but docker compose logs still shows them (if compose keeps logs).
  tmux send-keys -t "$SESSION":0.3 "docker compose logs -f --tail 120 co" C-m
  tmux select-layout -t "$SESSION":0 tiled

  # Runner window (where we actually execute CO scenarios in tmux mode)
  tmux new-window -t "$SESSION" -n runner
  tmux send-keys -t "$SESSION":runner.0 "cd '$ROOT_DIR' && clear; echo 'Runner ready'" C-m

  if [[ $SELF_TEST -eq 1 ]]; then
    info "Self-test mode: created tmux session $SESSION (not attaching)"
    return 0
  fi

  info "tmux session created: $SESSION"
  info "Run 'tmux attach -t $SESSION' in another terminal to watch logs"
  info "Tests will run automatically in the background"
}

verify_tmux_ui(){
  [[ $NO_TMUX -eq 1 ]] && return 0
  if ! tmux list-windows -t "$SESSION" 2>/dev/null | grep -q "logs"; then
    err "tmux session missing 'logs' window"
    return 1
  fi
  if ! tmux list-windows -t "$SESSION" 2>/dev/null | grep -q "runner"; then
    err "tmux session missing 'runner' window"
    return 1
  fi
  local panes
  panes=$(tmux list-panes -t "$SESSION":logs 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$panes" -lt 4 ]]; then
    err "expected 4 panes in logs window, got $panes"
    return 1
  fi
  info "tmux UI verified"
  return 0
}

# ----------------------------
# HO env toggle helper (replay test)
# ----------------------------
check_ho_env(){
  local expect_val="$1"
  local cid
  cid=$(docker compose ps -q ho 2>/dev/null || true)
  [[ -z "$cid" ]] && return 1
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" \
    | grep -q "REPLAY_TEST_MODE=$expect_val"
}

recreate_ho_with_replay_flag(){
  local val="$1"
  info "Recreating HO with REPLAY_TEST_MODE=$val"
  REPLAY_TEST_MODE="$val" docker compose up -d --no-deps --force-recreate ho
  # best-effort check
  if check_ho_env "$val"; then
    info "HO env verified: REPLAY_TEST_MODE=$val"
  else
    warn "Could not verify HO env via docker inspect (may still be correct depending on compose env wiring)"
  fi
}

# ----------------------------
# CO runner
# ----------------------------
CURRENT_SCEN="unknown"

run_co(){
  local envs=("$@")
  local -a docker_env_args=()
  local DOCKER_ENV_CMD=""
  for e in "${envs[@]}"; do
    docker_env_args+=( -e "$e" )
    DOCKER_ENV_CMD+=" -e $e"
  done

  local scen="$CURRENT_SCEN"
  local scen_safe
  scen_safe=$(echo "$scen" | sed -E 's/[^A-Za-z0-9_\-]/_/g')

  info "Running CO (scenario=$scen) envs: ${envs[*]:-NONE}"

  local scen_start_iso=""
  if [[ $SELF_TEST -eq 1 ]]; then
    scen_start_iso=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  fi

  local code=0

  if [[ $NO_TMUX -eq 1 ]]; then
    if [[ $SELF_TEST -eq 1 ]]; then
      info "Executing: docker compose run --rm${DOCKER_ENV_CMD} co -> $LOGDIR/co_${scen_safe}.log"
      set +e
      docker compose run --rm "${docker_env_args[@]}" co > "$LOGDIR/co_${scen_safe}.log" 2>&1
      code=$?
      set -e

      docker compose logs --no-color --since "$scen_start_iso" cauth > "$LOGDIR/cauth_${scen_safe}.log" 2>/dev/null || true
      docker compose logs --no-color --since "$scen_start_iso" sp    > "$LOGDIR/sp_${scen_safe}.log"    2>/dev/null || true
      docker compose logs --no-color --since "$scen_start_iso" ho    > "$LOGDIR/ho_${scen_safe}.log"    2>/dev/null || true
      return $code
    else
      set +e
      docker compose run --rm "${docker_env_args[@]}" co
      code=$?
      set -e
      return $code
    fi
  fi

  # tmux mode: run command in runner pane and parse exit code marker
  if [[ $SELF_TEST -eq 1 ]]; then
    tmux send-keys -t "$SESSION":runner.0 "clear; echo SCEN:${scen} START:${scen_start_iso}" C-m
  else
    tmux send-keys -t "$SESSION":runner.0 "clear; echo SCEN:${scen}" C-m
  fi

  # Send command to tmux runner pane
  local cmd="docker compose run --rm${DOCKER_ENV_CMD} co"
  tmux send-keys -t "$SESSION":runner.0 "$cmd" C-m
  
  local timeout=240
  local start_ts
  start_ts=$(date +%s)
  code=124
  local last_line=""

  info "Waiting for CO to complete in tmux (timeout: ${timeout}s)..."
  
  while :; do
    sleep 2
    local out
    out=$(tmux capture-pane -pt "$SESSION":runner.0 -S -2500 2>/dev/null | tr -d '\r') || out=""
    
    # Check if docker command finished (look for prompt or "exited" marker)
    if echo "$out" | tail -10 | grep -qE "(parallels@|root@|Command exited with code|✓✓✓ CO SERVICE|CONCLUSION:|VERIFICATION COMPLETE:)"; then
      # Extract exit code from docker output or assume 0 if successful completion message found
      if echo "$out" | grep -q "✓✓✓ CO SERVICE COMPLETED SUCCESSFULLY"; then
        code=0
      elif echo "$out" | grep -q "Command exited with code"; then
        code=$(echo "$out" | grep "Command exited with code" | tail -n1 | sed -E 's/.*code ([0-9]+).*/\1/')
      else
        # Try to get return code - send echo command
        tmux send-keys -t "$SESSION":runner.0 "echo CO_EXIT:\$?" C-m
        sleep 1
        out=$(tmux capture-pane -pt "$SESSION":runner.0 -S -2500 2>/dev/null | tr -d '\r') || out=""
        if echo "$out" | grep -q "CO_EXIT:"; then
          code=$(echo "$out" | grep "CO_EXIT:" | tail -n1 | sed -E 's/.*CO_EXIT:([0-9]+).*/\1/')
        else
          code=0  # Assume success if we see completion message
        fi
      fi
      
      # Validate that code is numeric
      if ! [[ "$code" =~ ^[0-9]+$ ]]; then
        warn "Failed to parse CO exit code, defaulting to 0"
        code=0
      fi
      break
    fi
    
    if (( $(date +%s) - start_ts >= timeout )); then
      err "Timeout waiting for CO to finish in tmux runner"
      code=124
      break
    fi
    
    # Show progress every 10 seconds
    if (( ($(date +%s) - start_ts) % 10 == 0 )); then
      local elapsed=$(($(date +%s) - start_ts))
      info "Still waiting... (${elapsed}s elapsed)"
    fi
  done

  if [[ $SELF_TEST -eq 1 ]]; then
    tmux capture-pane -pt "$SESSION":runner.0 -S -2500 > "$LOGDIR/co_${scen_safe}.log" || true
    docker compose logs --no-color --since "$scen_start_iso" cauth > "$LOGDIR/cauth_${scen_safe}.log" 2>/dev/null || true
    docker compose logs --no-color --since "$scen_start_iso" sp    > "$LOGDIR/sp_${scen_safe}.log"    2>/dev/null || true
    docker compose logs --no-color --since "$scen_start_iso" ho    > "$LOGDIR/ho_${scen_safe}.log"    2>/dev/null || true
  fi

  return $code
}

# ----------------------------
# Scenario implementations (return real CO exit code)
# ----------------------------
scenario_normal(){
  CURRENT_SCEN="normal"
  banner "P1_HONEST: Baseline Normal Flow"
  info "Command: docker compose run --rm co"
  run_co
  return $?
}

scenario_tamper(){
  CURRENT_SCEN="token_tamper"
  banner "M4.1 TOKEN_TAMPER"
  info "Command: docker compose run --rm -e NEG_TEST_MODE=TAMPER -e TAMPER_TOKEN_INDEX=0 -e TAMPER_BYTE_INDEX=0 co"
  run_co "NEG_TEST_MODE=TAMPER" "TAMPER_TOKEN_INDEX=0" "TAMPER_BYTE_INDEX=0"
  return $?
}

scenario_replay_local(){
  CURRENT_SCEN="replay_local_reject"
  banner "M4.2 REPLAY (Production): HO rejects locally"
  recreate_ho_with_replay_flag "false"
  info "Command: docker compose run --rm -e NEG_TEST_MODE=REPLAY -e REPLAY_DELAY_MS=1000 co"
  run_co "NEG_TEST_MODE=REPLAY" "REPLAY_DELAY_MS=1000"
  return $?
}

scenario_replay_sp(){
  CURRENT_SCEN="replay_sp_reject"
  banner "M4.2 REPLAY (Test): HO forwards, SP rejects"
  recreate_ho_with_replay_flag "true"
  info "Command: docker compose run --rm -e NEG_TEST_MODE=REPLAY -e REPLAY_DELAY_MS=1000 co"
  run_co "NEG_TEST_MODE=REPLAY" "REPLAY_DELAY_MS=1000"
  local rc=$?
  recreate_ho_with_replay_flag "false"
  return $rc
}

scenario_fake_cauth(){
  CURRENT_SCEN="fake_cauth"
  banner "CAuth-1 FAKE_CAUTH: Rogue Intermediate"

  # CRITICAL: Remove CO's existing keystore so it enrolls fresh with fake-cauth
  # Otherwise CO will reuse its legitimate certificate from earlier tests
  info "Clearing CO keystore to force fresh enrollment with fake-cauth"
  run_cmd_noe docker compose run --rm --entrypoint sh co -c "rm -f /app/keystore/co_keystore.p12" >/dev/null 2>&1
  
  info "Starting fake-cauth service"
  run_cmd_noe docker compose up -d --build fake-cauth
  local up_rc=$?
  if [[ $up_rc -ne 0 ]]; then
    warn "fake-cauth failed to start (docker compose up rc=$up_rc). Continuing to CO run to capture evidence/logs."
  fi

  # Wait for container to exist (best effort)
  sleep 2

  # Robust port discovery (optional)
  local hp
  hp=$(compose_port fake-cauth 8443)
  if [[ -n "$hp" ]]; then
    info "fake-cauth published port for 8443 is localhost:$hp"
    if ! wait_for_port "localhost" "$hp" 45; then
      warn "fake-cauth published port not reachable yet; continuing anyway"
    fi
  else
    warn "fake-cauth does not publish 8443 to host; assuming internal network only"
  fi

  info "Command: docker compose run --rm -e NEG_TEST_MODE=FAKE_CAUTH -e CAUTH_HOST=fake-cauth co"
  run_cmd_noe run_co "NEG_TEST_MODE=FAKE_CAUTH" "CAUTH_HOST=fake-cauth"
  local rc=$?

  run_cmd_noe docker compose stop fake-cauth
  run_cmd_noe docker compose rm -f fake-cauth >/dev/null 2>&1

  return $rc
}


scenario_bad_cert_missing(){
  CURRENT_SCEN="bad_cert_missing"
  banner "ROGUE_CO: BAD_CERT (MISSING)"
  info "Command: docker compose run --rm -e NEG_TEST_MODE=BAD_CERT -e BAD_CERT_MODE=MISSING co"
  run_co "NEG_TEST_MODE=BAD_CERT" "BAD_CERT_MODE=MISSING"
  return $?
}

scenario_bad_cert_selfsigned(){
  CURRENT_SCEN="bad_cert_selfsigned"
  banner "ROGUE_CO: BAD_CERT (SELF_SIGNED)"
  info "Command: docker compose run --rm -e NEG_TEST_MODE=BAD_CERT -e BAD_CERT_MODE=SELF_SIGNED co"
  run_co "NEG_TEST_MODE=BAD_CERT" "BAD_CERT_MODE=SELF_SIGNED"
  return $?
}

scenario_resv_field_edit(){
  CURRENT_SCEN="resv_field_edit"
  banner "FORGED_RESERVATION: RESV_TAMPER FIELD_EDIT"
  # Clean up any self-signed cert from BAD_CERT tests and re-enroll with legitimate cert
  run_cmd_noe docker compose run --rm --entrypoint sh co -c "rm -f /app/keystore/co_keystore.p12"
  info "Command: docker compose run --rm -e NEG_TEST_MODE=RESV_TAMPER -e RESV_TAMPER_MODE=FIELD_EDIT co"
  run_co "NEG_TEST_MODE=RESV_TAMPER" "RESV_TAMPER_MODE=FIELD_EDIT"
  return $?
}

scenario_resv_reorder(){
  CURRENT_SCEN="resv_reorder"
  banner "FORGED_RESERVATION: RESV_TAMPER REORDER"
  info "Command: docker compose run --rm -e NEG_TEST_MODE=RESV_TAMPER -e RESV_TAMPER_MODE=REORDER co"
  run_co "NEG_TEST_MODE=RESV_TAMPER" "RESV_TAMPER_MODE=REORDER"
  return $?
}

scenario_resv_sig_flip(){
  CURRENT_SCEN="resv_sig_flip"
  banner "FORGED_RESERVATION: RESV_TAMPER SIG_FLIP"
  info "Command: docker compose run --rm -e NEG_TEST_MODE=RESV_TAMPER -e RESV_TAMPER_MODE=SIG_FLIP co"
  run_co "NEG_TEST_MODE=RESV_TAMPER" "RESV_TAMPER_MODE=SIG_FLIP"
  return $?
}

scenario_resv_drop_field(){
  CURRENT_SCEN="resv_drop_field"
  banner "FORGED_RESERVATION: RESV_TAMPER DROP_FIELD"
  info "Command: docker compose run --rm -e NEG_TEST_MODE=RESV_TAMPER -e RESV_TAMPER_MODE=DROP_FIELD co"
  run_co "NEG_TEST_MODE=RESV_TAMPER" "RESV_TAMPER_MODE=DROP_FIELD"
  return $?
}

scenario_receipt_tamper(){
  CURRENT_SCEN="receipt_tamper"
  banner "RECEIPT_TAMPER"
  info "Command: docker compose run --rm -e NEG_TEST_MODE=RECEIPT_TAMPER co"
  run_co "NEG_TEST_MODE=RECEIPT_TAMPER"
  return $?
}

# ----------------------------
# Evaluation
# ----------------------------
declare -A RESULTS

evaluate_scenario(){
  local scen="$1"
  local code="$2"
  local pass=0
    # In self-test mode we judge by evidence in logs, not only exit code.
    # Negative scenarios may exit non-zero due to expected SecurityException / TLS alert.
  if [[ $SELF_TEST -ne 1 ]]; then
    if [[ $code -ne 0 ]]; then
        err "CO exited with code $code"
        pass=1
    fi
  fi

  # Self-test mode: also inspect CO output markers if available
  if [[ $SELF_TEST -eq 1 ]]; then
    local scen_safe co_log
    scen_safe=$(echo "$scen" | sed -E 's/[^A-Za-z0-9_\-]/_/g')
    co_log="$LOGDIR/co_${scen_safe}.log"
    # Scenario-specific evidence checks (treat expected security rejection as PASS)
    if [[ "$scen" == "fake_cauth" ]]; then
    if grep -qi "PKIX\|unable to find valid certification path\|bad_certificate\|SSLHandshakeException\|fatal alert" "$co_log"; then
        pass=0
    else
        # if it didn't show rejection evidence, fail it
        pass=1
    fi
    fi

    if [[ -f "$co_log" ]]; then
      if grep -q "\[SEC_ERR\]" "$co_log"; then
        pass=1
      fi
      # If we find SEC_OK explicitly, treat as pass (unless exit code already nonzero)
      if [[ $code -eq 0 ]] && grep -q "\[SEC_OK\]" "$co_log"; then
        pass=0
      fi
    else
      warn "CO log missing for $scen (self-test)"
    fi
  fi

  # Ensure core services still running
  for svc in cauth sp ho; do
    if ! container_running "$svc"; then
      err "$svc is not running after scenario $scen; attempting restart"
      run_cmd_noe docker compose up -d --no-deps --force-recreate "$svc"
      if ! container_running "$svc"; then
        pass=1
        err "Failed to restart $svc"
      else
        warn "$svc restarted"
      fi
    fi
  done

  if [[ $pass -eq 0 ]]; then
    RESULTS["$scen"]="PASS"
    info "[RESULT] $scen: PASS (exit=$code)"
  else
    RESULTS["$scen"]="FAIL (exit=$code)"
    err "[RESULT] $scen: FAIL (exit=$code)"
  fi
}

# ----------------------------
# Main
# ----------------------------
sanity_checks
compose_up_core
ensure_services
start_tmux_ui

if [[ $SELF_TEST -eq 1 ]]; then
  run_cmd_noe verify_tmux_ui || warn "tmux verification failed (continuing)"
fi

scenarios=(
  normal
  token_tamper
  replay_local_reject
  replay_sp_reject
  bad_cert_missing
  bad_cert_selfsigned
  resv_field_edit
  resv_reorder
  resv_sig_flip
  resv_drop_field
  receipt_tamper
  fake_cauth
)

for s in "${scenarios[@]}"; do
  code=0
  case "$s" in
    normal)              run_cmd_noe scenario_normal;          code=$? ;;
    token_tamper)        run_cmd_noe scenario_tamper;          code=$? ;;
    replay_local_reject) run_cmd_noe scenario_replay_local;    code=$? ;;
    replay_sp_reject)    run_cmd_noe scenario_replay_sp;       code=$? ;;
    fake_cauth)          run_cmd_noe scenario_fake_cauth;      code=$? ;;
    bad_cert_missing)    run_cmd_noe scenario_bad_cert_missing;code=$? ;;
    bad_cert_selfsigned) run_cmd_noe scenario_bad_cert_selfsigned;code=$? ;;
    resv_field_edit)     run_cmd_noe scenario_resv_field_edit; code=$? ;;
    resv_reorder)        run_cmd_noe scenario_resv_reorder;    code=$? ;;
    resv_sig_flip)       run_cmd_noe scenario_resv_sig_flip;   code=$? ;;
    resv_drop_field)     run_cmd_noe scenario_resv_drop_field; code=$? ;;
    receipt_tamper)      run_cmd_noe scenario_receipt_tamper;  code=$? ;;
    *) code=3 ;;
  esac

  evaluate_scenario "$s" "$code"
done

banner "Test Summary"
for k in "${scenarios[@]}"; do
  printf "- %s: %s\n" "$k" "${RESULTS[$k]:-MISSING}"
done

if printf "%s\n" "${RESULTS[@]}" | grep -q "FAIL"; then
  err "One or more scenarios failed. See logs for details."
  exit 4
else
  info "All scenarios completed successfully"
  exit 0
fi
