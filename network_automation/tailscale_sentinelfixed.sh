#!/bin/bash

# --- DATA LAYER ---
status_acts=("Show All Machines" "Return IPv4" "Activity" "Back" "Exit")
log_acts=("Web Access Link" "SSH locally" "Back" "Exit")
config_acts=("Netcheck" "Config Wipe Reset" "Force traffic to OCI" "Switch to Tnet" "Ping Zombie" "Bug Report" "Back" "Exit")

# --- MAIN LOOP ---
while true; do
    echo "---  TAILSCALE SERVICE MANAGER ---"
    
    # Reset the prompt for the top level
    PS3="Select Category: "
    
    select env in "Check Status" "Login" "Configs" "Exit"; do
       case "$env" in
           "Check Status")
              current_acts=("${status_acts[@]}")
              break 
              ;;
            "Login")
              current_acts=("${log_acts[@]}")
              break
              ;;
            "Configs")
              # FIXED: Removed the extra 's' typo
              current_acts=("${config_acts[@]}")
              break
              ;;
            "Exit") exit 0 ;;
            *) echo "Invalid option $REPLY";;
       esac
    done       

    # --- SUB-MENU LAYER ---
    echo "--- Accessing: $env ---"
    
    # FIXED: Changed 'mageu' to 'PS3' so the menu actually updates
    PS3="[$env] Select Action: "
    
    select task in "${current_acts[@]}"; do
        case "$task" in
             "Back") break ;; 
             "Exit") exit 0 ;;
             
             # Status Actions
             "Show All Machines") sudo tailscale status ;;
             "Return IPv4")       sudo tailscale ip -4 ;;
             "Activity")          systemctl is-active tailscaled ;;
             
             # Login Actions
             "Web Access Link")   sudo tailscale up ;;
             "SSH locally")       ssh Master ;;
             
             # Config Actions
             "Netcheck")          sudo tailscale netcheck ;;
             "Config Wipe Reset") 
                  # Added safety prompt because this is destructive
                  read -p "⚠️ Reset Config? (y/n): " confirm
                  [[ "$confirm" == "y" ]] && sudo tailscale up --reset 
                  ;;
             "Force traffic to OCI") sudo tailscale up --exit-node="100.x.y.z" ;; #
             "Switch to Tnet")    sudo tailscale up --advertise-exit-node ;;
             "Ping Node")       tailscale ping 100.x.y.z ;; # sudo not usually needed for ping
             "Bug Report")        sudo tailscale bugreport ;;
        esac
        
        # Pause to let user read output before menu reappears
        echo ""
        read -p "Press Enter to continue..."
    done
done

