#!/bin/bash

# Check if $1 (commands file) is provided
if [ -z "$1" ]; then
  echo "Commands file not provided. Please supply a commands file as the first argument."
  echo "Usage: ecs-eks-test.sh <commands_file> [cluster_name]"
  exit 1
fi

COMMANDS_FILE="$1"

# Check if $2 (cluster name) is provided
if [ -z "$2" ]; then
  echo "Cluster name not provided, trying to connect to the cluster ecs-$CLUSTER_NAME"
  ECS_CLUSTER_NAME="ecs-$CLUSTER_NAME"
else
  ECS_CLUSTER_NAME="$2"
  echo "Connecting to the specified cluster: $ECS_CLUSTER_NAME"
fi

# Automatically retrieve the Task ID
TASK_ID=$(aws ecs list-tasks \
  --cluster "$ECS_CLUSTER_NAME" \
  --service-name "shell-task" \
  --query 'taskArns[0]' \
  --output text | cut -d'/' -f3)

echo "Using Task ID: $TASK_ID"

# Check if TASK_ID is empty or null
if [ -z "$TASK_ID" ]; then
  echo "Failed to retrieve task ID. Exiting."
  exit 1
fi

# Check if the commands file exists and is readable
if [ ! -f "$COMMANDS_FILE" ] || [ ! -r "$COMMANDS_FILE" ]; then
  echo "The commands file either doesn't exist or is not readable: $COMMANDS_FILE"
  exit 1
fi

# Read the commands from the file into an array
commands=()
while IFS= read -r line || [ -n "$line" ]; do
    # Clean up any trailing carriage returns (e.g., from Windows-style newlines)
    line=$(echo "$line" | tr -d '\r' | xargs)
    if [[ -n "$line" ]]; then
        commands+=("$line")
    fi
done < "$COMMANDS_FILE"

# Iterate over the commands array and execute them remotely in the ECS task container
for cmd in "${commands[@]}"; do
    # Prepend the SOCKS5 proxy to the curl command
    final_cmd="sh -c 'curl $cmd'"

    # Add a separator between commands
    echo "-----"
    echo "Running command: curl $cmd"

    # Execute the command on the ECS task, filtering out unnecessary and empty lines
    output=$(aws ecs execute-command \
        --cluster "$ECS_CLUSTER_NAME" \
        --task "$TASK_ID" \
        --container "shell-task" \
        --interactive \
        --command "$final_cmd" 2>&1 | grep -v "Starting session with" | grep -v "Exiting session with" | grep -v "The Session Manager plugin was installed successfully" | grep -v '^$')

    # Print the raw output of the command for debugging
    echo "$output"

done
