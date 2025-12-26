#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════
# Security Test Suite - Interactive Dashboard
# ═══════════════════════════════════════════════════════════════════════════
# This script creates a 6-pane tmux dashboard that shows real-time logs
# from all services and runs all security test scenarios automatically.
#
# Layout:
#  ┌──────────────┬──────────────┬──────────────┐
#  │   CAUTH      │      SP      │      HO      │  ← Core services
#  ├──────────────┼──────────────┼──────────────┤
#  │     CO       │  FAKE-CAUTH  │ TEST RUNNER  │  ← Test execution
#  └──────────────┴──────────────┴──────────────┘
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

SESSION="security-test-suite"

echo "════════════════════════════════════════════════════════════════"
echo "  Starting Security Test Suite Dashboard"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Kill previous session
tmux kill-session -t $SESSION 2>/dev/null || true

# Clean up previous run
echo "Cleaning up previous containers..."
sudo docker compose down -v 2>/dev/null || true

# Make test runner executable
chmod +x ./run_all_scenarios.sh

# Create new tmux session (avoiding nested warning)
TMUX= tmux new-session -d -s $SESSION

# ═══════════════════════════════════════════════════════════════════════════
# Create 6-pane layout
# ═══════════════════════════════════════════════════════════════════════════

# Pane 0: CAUTH (top-left)
tmux select-pane -t $SESSION:0.0 -T "CAUTH"

# Pane 1: SP (split right from pane 0)
tmux split-window -h -t $SESSION:0.0
tmux select-pane -t $SESSION:0.1 -T "SP"

# Pane 2: HO (split right from pane 1)
tmux split-window -h -t $SESSION:0.1
tmux select-pane -t $SESSION:0.2 -T "HO"

# Pane 3: CO (split below pane 0)
tmux split-window -v -t $SESSION:0.0
tmux select-pane -t $SESSION:0.3 -T "CO"

# Pane 4: FAKE-CAUTH (split below pane 1)
tmux split-window -v -t $SESSION:0.1
tmux select-pane -t $SESSION:0.4 -T "FAKE-CAUTH"

# Pane 5: TEST RUNNER (split below pane 2)
tmux split-window -v -t $SESSION:0.2
tmux select-pane -t $SESSION:0.5 -T "TEST RUNNER"

# ═══════════════════════════════════════════════════════════════════════════
# Configure each pane
# ═══════════════════════════════════════════════════════════════════════════

# Pane 0: CAUTH logs
tmux send-keys -t $SESSION:0.0 "echo '═══════════════════════════════════════════════════════════════'" C-m
tmux send-keys -t $SESSION:0.0 "echo '  CAUTH - Certificate Authority'" C-m
tmux send-keys -t $SESSION:0.0 "echo '  Real CA issuing legitimate certificates'" C-m
tmux send-keys -t $SESSION:0.0 "echo '═══════════════════════════════════════════════════════════════'" C-m
tmux send-keys -t $SESSION:0.0 "echo ''" C-m
tmux send-keys -t $SESSION:0.0 "echo 'Waiting for test runner to start services...'" C-m
tmux send-keys -t $SESSION:0.0 "sleep 2" C-m
tmux send-keys -t $SESSION:0.0 "sudo docker compose logs -f --tail 100 cauth 2>/dev/null || echo 'Waiting for cauth to start...'" C-m

# Pane 1: SP logs
tmux send-keys -t $SESSION:0.1 "echo '═══════════════════════════════════════════════════════════════'" C-m
tmux send-keys -t $SESSION:0.1 "echo '  SP - Service Provider'" C-m
tmux send-keys -t $SESSION:0.1 "echo '  Token verification and settlement endpoint'" C-m
tmux send-keys -t $SESSION:0.1 "echo '═══════════════════════════════════════════════════════════════'" C-m
tmux send-keys -t $SESSION:0.1 "echo ''" C-m
tmux send-keys -t $SESSION:0.1 "echo 'Waiting for test runner to start services...'" C-m
tmux send-keys -t $SESSION:0.1 "sleep 2" C-m
tmux send-keys -t $SESSION:0.1 "sudo docker compose logs -f --tail 100 sp 2>/dev/null || echo 'Waiting for sp to start...'" C-m

# Pane 2: HO logs (with auto-reconnect for container restarts)
tmux send-keys -t $SESSION:0.2 "echo '═══════════════════════════════════════════════════════════════'" C-m
tmux send-keys -t $SESSION:0.2 "echo '  HO - Home Owner'" C-m
tmux send-keys -t $SESSION:0.2 "echo '  Payment acceptance and verification'" C-m
tmux send-keys -t $SESSION:0.2 "echo '═══════════════════════════════════════════════════════════════'" C-m
tmux send-keys -t $SESSION:0.2 "echo ''" C-m
tmux send-keys -t $SESSION:0.2 "echo 'Waiting for test runner to start services...'" C-m
tmux send-keys -t $SESSION:0.2 "sleep 2" C-m
tmux send-keys -t $SESSION:0.2 "while true; do" C-m
tmux send-keys -t $SESSION:0.2 "  if sudo docker compose ps ho 2>/dev/null | grep -q 'Up'; then" C-m
tmux send-keys -t $SESSION:0.2 "    sudo docker compose logs -f --tail 100 ho 2>/dev/null" C-m
tmux send-keys -t $SESSION:0.2 "  fi" C-m
tmux send-keys -t $SESSION:0.2 "  sleep 2" C-m
tmux send-keys -t $SESSION:0.2 "done" C-m

# Pane 3: CO logs (follow running CO containers)
tmux send-keys -t $SESSION:0.3 "echo '═══════════════════════════════════════════════════════════════'" C-m
tmux send-keys -t $SESSION:0.3 "echo '  CO - Car Owner (Client)'" C-m
tmux send-keys -t $SESSION:0.3 "echo '  Runs test scenarios with various attack modes'" C-m
tmux send-keys -t $SESSION:0.3 "echo '═══════════════════════════════════════════════════════════════'" C-m
tmux send-keys -t $SESSION:0.3 "echo ''" C-m
tmux send-keys -t $SESSION:0.3 "echo 'Waiting for CO test containers to start...'" C-m
tmux send-keys -t $SESSION:0.3 "echo '(CO runs as one-off containers via test runner)'" C-m
tmux send-keys -t $SESSION:0.3 "echo ''" C-m
tmux send-keys -t $SESSION:0.3 "sleep 3" C-m
tmux send-keys -t $SESSION:0.3 "while true; do" C-m
tmux send-keys -t $SESSION:0.3 "  CO_CONTAINER=\$(sudo docker ps --filter 'name=.*-co-' --format '{{.Names}}' | head -1)" C-m
tmux send-keys -t $SESSION:0.3 "  if [ -n \"\$CO_CONTAINER\" ]; then" C-m
tmux send-keys -t $SESSION:0.3 "    echo \"Following logs from: \$CO_CONTAINER\"" C-m
tmux send-keys -t $SESSION:0.3 "    sudo docker logs -f \"\$CO_CONTAINER\" 2>&1 || true" C-m
tmux send-keys -t $SESSION:0.3 "  fi" C-m
tmux send-keys -t $SESSION:0.3 "  sleep 1" C-m
tmux send-keys -t $SESSION:0.3 "done" C-m

# Pane 4: FAKE-CAUTH logs (monitor for when it's started)
tmux send-keys -t $SESSION:0.4 "echo '═══════════════════════════════════════════════════════════════'" C-m
tmux send-keys -t $SESSION:0.4 "echo '  FAKE-CAUTH - Rogue Certificate Authority'" C-m
tmux send-keys -t $SESSION:0.4 "echo '  Self-signed CA for negative testing (CAuth-1)'" C-m
tmux send-keys -t $SESSION:0.4 "echo '  Only active during rogue CA test scenario'" C-m
tmux send-keys -t $SESSION:0.4 "echo '═══════════════════════════════════════════════════════════════'" C-m
tmux send-keys -t $SESSION:0.4 "echo ''" C-m
tmux send-keys -t $SESSION:0.4 "echo 'Status: Waiting for CAuth-1 test...'" C-m
tmux send-keys -t $SESSION:0.4 "while true; do" C-m
tmux send-keys -t $SESSION:0.4 "  if sudo docker compose ps fake-cauth 2>/dev/null | grep -q 'Up'; then" C-m
tmux send-keys -t $SESSION:0.4 "    sudo docker compose logs -f --tail 50 fake-cauth" C-m
tmux send-keys -t $SESSION:0.4 "    break" C-m
tmux send-keys -t $SESSION:0.4 "  fi" C-m
tmux send-keys -t $SESSION:0.4 "  sleep 2" C-m
tmux send-keys -t $SESSION:0.4 "done" C-m

# Pane 5: TEST RUNNER (orchestrator)
tmux send-keys -t $SESSION:0.5 "clear" C-m
tmux send-keys -t $SESSION:0.5 "./run_all_scenarios.sh" C-m

# ═══════════════════════════════════════════════════════════════════════════
# Final configuration
# ═══════════════════════════════════════════════════════════════════════════

# Adjust pane sizes to make them even
tmux select-layout -t $SESSION:0 tiled

# Enable mouse scrolling and large history
tmux set-option -g mouse on
tmux set-option -g history-limit 50000

# Set pane border colors for better visibility
tmux set-option -g pane-border-style fg=colour240
tmux set-option -g pane-active-border-style fg=colour51

# Status bar configuration
tmux set-option -g status-style bg=colour235,fg=colour252
tmux set-option -g status-left-length 40
tmux set-option -g status-left "#[fg=colour51,bold] Security Test Suite #[fg=colour252]| "
tmux set-option -g status-right "#[fg=colour252]%H:%M:%S "

# Initial focus on test runner
tmux select-pane -t $SESSION:0.5

# Attach to session
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Dashboard started! Attaching to tmux session..."
echo "  Press Ctrl+B then Q to see pane numbers"
echo "  Press Ctrl+B then arrow keys to navigate between panes"
echo "  Press Ctrl+B then D to detach (dashboard keeps running)"
echo "════════════════════════════════════════════════════════════════"
echo ""

sleep 1

# Attach to session
if command -v byobu >/dev/null 2>&1; then
    BYOBU_DISABLE_PROMPT=1 byobu attach -t $SESSION
else
    tmux attach -t $SESSION
fi
