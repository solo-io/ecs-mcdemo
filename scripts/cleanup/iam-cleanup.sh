#!/bin/bash

EXECUTION_ROLE_NAME=ecs-task-execution-role
EXECUTION_POLICY_ARN=arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
TASK_ROLE_NAME=eks-ecs-task-role
TASK_POLICY_NAME=eks-ecs-task-policy

echo "Starting cleanup of IAM roles and policies..."

# Get the task policy ARN
TASK_POLICY_ARN=$(aws iam list-policies \
    --query "Policies[?PolicyName=='$TASK_POLICY_NAME'].Arn" \
    --output text)

# Cleanup Task Role
if aws iam get-role --role-name $TASK_ROLE_NAME > /dev/null 2>&1; then
    echo "Detaching policies from $TASK_ROLE_NAME..."
    
    # Detach task policy
    if [ ! -z "$TASK_POLICY_ARN" ]; then
        aws iam detach-role-policy \
            --role-name $TASK_ROLE_NAME \
            --policy-arn $TASK_POLICY_ARN
        echo "Detached $TASK_POLICY_NAME from $TASK_ROLE_NAME"
    fi
    
    echo "Deleting role $TASK_ROLE_NAME..."
    aws iam delete-role --role-name $TASK_ROLE_NAME
    echo "Deleted role $TASK_ROLE_NAME"
else
    echo "Task role $TASK_ROLE_NAME does not exist."
fi

# Delete Task Policy
if [ ! -z "$TASK_POLICY_ARN" ]; then
    echo "Deleting policy $TASK_POLICY_NAME..."
    aws iam delete-policy --policy-arn $TASK_POLICY_ARN
    echo "Deleted policy $TASK_POLICY_NAME"
else
    echo "Task policy $TASK_POLICY_NAME does not exist."
fi

# Cleanup Execution Role
if aws iam get-role --role-name $EXECUTION_ROLE_NAME > /dev/null 2>&1; then
    echo "Detaching policies from $EXECUTION_ROLE_NAME..."
    
    # Detach execution policy
    aws iam detach-role-policy \
        --role-name $EXECUTION_ROLE_NAME \
        --policy-arn $EXECUTION_POLICY_ARN
    echo "Detached $EXECUTION_POLICY_ARN from $EXECUTION_ROLE_NAME"
    
    echo "Deleting role $EXECUTION_ROLE_NAME..."
    aws iam delete-role --role-name $EXECUTION_ROLE_NAME
    echo "Deleted role $EXECUTION_ROLE_NAME"
else
    echo "Execution role $EXECUTION_ROLE_NAME does not exist."
fi

echo "Cleanup completed."