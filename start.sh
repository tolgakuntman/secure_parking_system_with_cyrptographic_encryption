#!/bin/bash
docker compose down -v
clear
docker compose up --build -d cauth sp co

SESSION="fourbuilds"

# Kill previous session
tmux kill-session -t $SESSION 2>/dev/null

# Force a new tmux session (avoiding nested warning)
TMUX= tmux new-session -d -s $SESSION

# Top-left: CAUTH (pane 0)
tmux select-pane -T "CAUTH"

# Top-right: SP (pane 1)
tmux split-window -h -t $SESSION:0.0
tmux select-pane -T "SP"

# Bottom-left: HO (pane 2)
tmux select-pane -t $SESSION:0.0
tmux split-window -v -t $SESSION:0.0
tmux select-pane -T "HO"

# Bottom-right: CO (pane 3)
tmux select-pane -t $SESSION:0.1
tmux split-window -v -t $SESSION:0.1

tmux send-keys -t $SESSION:0.0 "docker compose logs -f --tail 200 cauth" C-m
tmux send-keys -t $SESSION:0.1 "docker compose logs -f --tail 200 sp" C-m
tmux send-keys -t $SESSION:0.2 "docker compose logs -f --tail 200 ho" C-m
tmux send-keys -t $SESSION:0.3 "docker compose logs -f --tail 200 co" C-m

# Tile layout to make it perfect
tmux select-layout -t $SESSION:0 tiled

# Enable mouse scrolling and history
tmux set-option -g mouse on
tmux set-option -g history-limit 10000

# Attach inside Byobu
BYOBU_DISABLE_PROMPT=1 byobu attach -t $SESSION
