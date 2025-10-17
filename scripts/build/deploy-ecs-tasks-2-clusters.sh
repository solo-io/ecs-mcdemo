#!/bin/bash
#
# 
# This script will create the ECS infrastructure on AWS
#  It will create 2 ECS clusters

# Check if required environment variables are defined
required_vars=("TASK_ROLE_ARN" "ECS_SERVICE_ACCOUNT_NAME" "AWS_REGION" "CLUSTER_NAME" "OWNER_NAME")
for var in "${required_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "Error: $var is not defined."
    exit 1
  fi
done

# Define task definitions for easier loop processing
task_definitions=("shell-task-definition.json" "echo-task-definition.json")
log_prefixes=("demo-shell-task" "echo-service-task")

# Function to register task definition
register_task_definition() {
  local task_def=$1
  local log_prefix=$2

  echo "Registering task definition for $task_def..."

  # Define jq filter for task definition
  jq_filter='.taskRoleArn = $taskRole |
             .executionRoleArn = $taskRole |
             .tags = [{"key": "ecs.solo.io/service-account", "value": $svcAcct}, {"key": "environment", "value": "ecs-demo"}] |
             .containerDefinitions[0].logConfiguration |= { "logDriver": "awslogs", "options": { "awslogs-group": "/ecs/ecs-demo", "awslogs-region": $awsRegion, "awslogs-stream-prefix": $logPrefix } }'

  # Register the ECS task definition
  aws ecs register-task-definition \
    --cli-input-json "$(jq --arg taskRole "$TASK_ROLE_ARN" \
                             --arg svcAcct "$ECS_SERVICE_ACCOUNT_NAME" \
                             --arg awsRegion "$AWS_REGION" \
                             --arg logPrefix "$log_prefix" \
                             "$jq_filter" \
                             ecs_definitions/$task_def)" > /dev/null

  # Check if the task registration is successful
  if [ $? -ne 0 ]; then
    echo "Error: Task definition registration failed for $task_def."
    exit 1
  fi
  echo "Task definition $task_def registered successfully."
}

# Loop through task definitions and register each
for i in "${!task_definitions[@]}"; do
  register_task_definition "${task_definitions[$i]}" "${log_prefixes[$i]}"
done

echo "All task definitions registered successfully."

# Get VPC ID for the ECS cluster
export ecs_vpc_id=$(aws eks describe-cluster \
  --name "$CLUSTER_NAME" \
  --region "$AWS_REGION" \
  --query 'cluster.resourcesVpcConfig.vpcId' \
  --output text)

# Check if ecs_vpc_id is empty
if [ -z "$ecs_vpc_id" ]; then
  echo "Error: Failed to retrieve VPC ID."
  exit 1
fi
echo "ecs_vpc_id: $ecs_vpc_id"  

# Get Private Subnet IDs for ECS
export ecs_private_subnet_ids=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values="$ecs_vpc_id" Name=map-public-ip-on-launch,Values=false \
  --query 'Subnets[*].SubnetId' \
  --output text | tr '\t' ',')

# Check if ecs_private_subnet_ids is empty
if [ -z "$ecs_private_subnet_ids" ]; then
  echo "Error: Failed to retrieve private subnet IDs."
  exit 1
fi

echo "Private Subnet IDs: $ecs_private_subnet_ids"

# Check if the security group already exists
existing_sg=$(aws ec2 describe-security-groups \
  --filters Name=group-name,Values=ecs-demo-sg \
  --query "SecurityGroups[0].GroupId" \
  --output text)

if [ "$existing_sg" != "None" ]; then
  echo "Security group 'ecs-demo-sg' already exists, skipping creation."
else
  # Create ECS security group if it doesn't exist
  aws ec2 create-security-group \
    --group-name ecs-demo-sg \
    --description "Security Group for ECS Demo" \
    --vpc-id $ecs_vpc_id > /dev/null

  # Check if the security group creation was successful
  if [ $? -ne 0 ]; then
    echo "Error: Failed to create ECS security group."
  fi
fi

export ecs_security_group=$(aws ec2 describe-security-groups --filters Name=group-name,Values=ecs-demo-sg --query "SecurityGroups[0].GroupId" --output text)

# Check if ecs_security_group is empty
if [ -z "$ecs_security_group" ]; then
  echo "Error: Failed to retrieve security groups."
  exit 1
fi

echo "Security Group IDs: $ecs_security_group"

# Add tags to the security group
aws ec2 create-tags \
  --resources $ecs_security_group \
  --tags Key=environment,Value=ecs-demo > /dev/null

# Check if tagging was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to add tags to security group."
fi

# Authorize ingress for the security group
aws ec2 authorize-security-group-ingress \
  --group-id $ecs_security_group \
  --protocol -1 --port 0-65535 --cidr 0.0.0.0/0 > /dev/null

# Check if ingress authorization was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to authorize ingress for security group."
fi

# Create ECS cluster-1
aws ecs create-cluster --cluster ecs-$CLUSTER_NAME-1 > /dev/null

# Check if cluster creation was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to create ECS cluster."
  exit 1
fi

# Create ECS cluster-2
aws ecs create-cluster --cluster ecs-$CLUSTER_NAME-2 > /dev/null

# Check if cluster creation was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to create ECS cluster."
  exit 1
fi

# Create CloudWatch log group
aws logs create-log-group --log-group-name "/ecs/ecs-demo" --region $AWS_REGION > /dev/null

# Check if log group creation was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to create log group."
fi

# Create ECS services in ecs-cluster-1
services=("shell-task" "echo-service")

for service in "${services[@]}"; do
  aws ecs create-service \
    --cluster ecs-$CLUSTER_NAME-1 \
    --service-name $service \
    --task-definition $service-definition \
    --desired-count 1 \
    --launch-type FARGATE \
    --enable-execute-command \
    --network-configuration "awsvpcConfiguration={subnets=[$ecs_private_subnet_ids],securityGroups=[$ecs_security_group],assignPublicIp=DISABLED}" > /dev/null

  # Check if the service creation was successful
  if [ $? -ne 0 ]; then
    echo "Error: Failed to create ECS service for $service."
  fi
done

# Create ECS services in ecs-cluster-2
services=("shell-task" "echo-service")

for service in "${services[@]}"; do
  aws ecs create-service \
    --cluster ecs-$CLUSTER_NAME-2 \
    --service-name $service \
    --task-definition $service-definition \
    --desired-count 1 \
    --launch-type FARGATE \
    --enable-execute-command \
    --network-configuration "awsvpcConfiguration={subnets=[$ecs_private_subnet_ids],securityGroups=[$ecs_security_group],assignPublicIp=DISABLED}" > /dev/null

  # Check if the service creation was successful
  if [ $? -ne 0 ]; then
    echo "Error: Failed to create ECS service for $service."
  fi
done

echo "ECS services script is completed."

# Get the security group ID for the EKS cluster
EKS_SG_ID=$(aws ec2 describe-security-groups \
  --filters Name=vpc-id,Values=$(aws eks describe-cluster \
  --name "$CLUSTER_NAME" \
  --region "$AWS_REGION" \
  --query 'cluster.resourcesVpcConfig.vpcId' \
  --output text) \
           Name=group-name,Values='eks-cluster-sg*' \
  --query 'SecurityGroups[0].GroupId' \
  --output text)

# Authorize ingress for the security group (allow all traffic from any IP, can be restricted later)
aws ec2 authorize-security-group-ingress \
  --group-id $EKS_SG_ID \
  --protocol -1 \
  --cidr 0.0.0.0/0 \
  --no-cli-pager > /dev/null 2>&1

echo "Ingress authorized for EKS security group $EKS_SG_ID (for ECS demo purposes)."
