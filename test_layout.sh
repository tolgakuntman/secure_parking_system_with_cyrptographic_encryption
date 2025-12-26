#!/bin/bash

# Quick test to verify the dashboard layout works
# Run this if you want to see the layout without running tests

SESSION="layout-test"

echo "Creating 6-pane layout preview..."

# Kill previous session
tmux kill-session -t $SESSION 2>/dev/null || true

# Create new session
TMUX= tmux new-session -d -s $SESSION

# Create layout
tmux select-pane -t $SESSION:0.0 -T "CAUTH"
tmux split-window -h -t $SESSION:0.0
tmux select-pane -t $SESSION:0.1 -T "SP"
tmux split-window -h -t $SESSION:0.1
tmux select-pane -t $SESSION:0.2 -T "HO"
tmux split-window -v -t $SESSION:0.0
tmux select-pane -t $SESSION:0.3 -T "CO"
tmux split-window -v -t $SESSION:0.1
tmux select-pane -t $SESSION:0.4 -T "FAKE-CAUTH"
tmux split-window -v -t $SESSION:0.2
tmux select-pane -t $SESSION:0.5 -T "TEST RUNNER"

# Add content to each pane
tmux send-keys -t $SESSION:0.0 "echo 'CAUTH - Certificate Authority'; echo 'Issues legitimate certificates'; sleep 100" C-m
tmux send-keys -t $SESSION:0.1 "echo 'SP - Service Provider'; echo 'Token verification endpoint'; sleep 100" C-m
tmux send-keys -t $SESSION:0.2 "echo 'HO - Home Owner'; echo 'Payment acceptance'; sleep 100" C-m
tmux send-keys -t $SESSION:0.3 "echo 'CO - Car Owner'; echo 'Test client'; sleep 100" C-m
tmux send-keys -t $SESSION:0.4 "echo 'FAKE-CAUTH - Rogue CA'; echo 'Attack simulator'; sleep 100" C-m
tmux send-keys -t $SESSION:0.5 "echo 'TEST RUNNER - Orchestrator'; echo 'Controls test execution'; sleep 100" C-m

# Apply layout
tmux select-layout -t $SESSION:0 tiled

# Configure
tmux set-option -g mouse on
tmux set-option -g history-limit 50000

echo "Layout created! Attaching..."
echo "Press Ctrl+B then D to exit"
echo ""

sleep 1
tmux attach -t $SESSION
