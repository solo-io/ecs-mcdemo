terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Owner = var.owner_name
    }
  }
}

# Variables
variable "aws_region" {
  type        = string
  description = "AWS region"
}

variable "owner_name" {
  type        = string
  description = "Owner of the resources"
}

variable "ecs_task_role_arn" {
  type        = string
  description = "ECS Task Role"
}

variable "ecs_execution_role_arn" {
  type        = string
  description = "ECS Execution Role"
}

variable "ecs_service_account_name" {
  type        = string
  description = "ECS Service Account"
}


variable "cluster_name" {
  type        = string
  description = "Name of the existing EKS cluster"
}

variable "vpc_id" {}


variable "ECHO_TOKEN" {
  type = string
}

variable "SHELL_TOKEN" {
  type = string
}

# Fetch existing EKS cluster information
data "aws_eks_cluster" "eks" {
  name = var.cluster_name
}

# Assign EKS VPC ID to the cluster
data "aws_vpc" "eks_vpc" {
  id = var.vpc_id
}

# Fetch private subnets in the VPC
data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.eks_vpc.id]
  }
}

# Local variables for the ECS cluster and image
locals {
  ecs_cluster_name = "ecs-${var.cluster_name}"
  ztunnel_image    = "mcallisterpetr/ztunnel:1.24-alpha.fa3b8447e4d7c0d4d0167d4de9ad51991330b6f3"
}

# Cloud Map (Service Discovery)
resource "aws_service_discovery_private_dns_namespace" "this" {
  name = local.ecs_cluster_name
  vpc  = data.aws_vpc.eks_vpc.id
}

resource "aws_service_discovery_service" "echo-ztunnel" {
  name        = "echo-ztunnel"
  description = "CloudMap namespace for echo"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.this.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
}

# ECS Cluster
module "ecs_cluster" {
  source  = "terraform-aws-modules/ecs/aws//modules/cluster"
  version = "~> 5.11"

  cluster_name = local.ecs_cluster_name
}

resource "aws_ecs_task_definition" "ztunnel_task" {
  family                   = "ztunnel"
  cpu                      = "256"
  memory                   = "512"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  
  task_role_arn      = var.ecs_task_role_arn

  container_definitions = <<DEFINITION
  [
    {
      "name": "echo",
      "image": "gcr.io/istio-testing/app",
      "memory": 512,
      "cpu": 256,
      "portMappings": [
        {
          "containerPort": 8080,
          "hostPort": 8080,
          "protocol": "tcp"
        }
      ]
    },
    {
      "name": "ztunnel",
      "image": "${local.ztunnel_image}",
      "environment": [
        {
          "name": "BOOTSTRAP_TOKEN",
          "value": "${var.ECHO_TOKEN}"
        }
      ]
    }
  ]
  DEFINITION
  tags = {
    "ecs.solo.io/service-account" = var.ecs_service_account_name
  }
}

resource "aws_security_group" "ecs_service_sg" {
  vpc_id = data.aws_vpc.eks_vpc.id

  # Egress rule allowing all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Ingress rule allowing all inbound traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_ecs_service" "echo_ztunnel_service" {
  name            = "echo-ztunnel"
  cluster         = module.ecs_cluster.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  task_definition = aws_ecs_task_definition.ztunnel_task.arn

  network_configuration {
    subnets         = data.aws_subnets.private.ids
    assign_public_ip = true

    security_groups = [aws_security_group.ecs_service_sg.id]
  }

  service_registries {
    registry_arn = aws_service_discovery_service.echo-ztunnel.arn
  }
  
  tags = {
    "ecs.solo.io/service-account" = var.ecs_service_account_name
  }
}

# CloudWatch Log Group for ztunnel-shell
resource "aws_cloudwatch_log_group" "ztunnel_shell_log_group" {
  name              = "/ecs/${local.ecs_cluster_name}/ztunnel-shell"
  retention_in_days = 3 
  tags = {
    Owner = var.owner_name
  }
}

resource "aws_ecs_task_definition" "shell_task" {
  family                   = "shell"
  cpu                      = "256"
  memory                   = "512"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  
  task_role_arn            = var.ecs_task_role_arn
  execution_role_arn       = var.ecs_execution_role_arn

  container_definitions = <<DEFINITION
  [
    {
      "name": "shell",
      "image": "curlimages/curl:latest",
      "memory": 512,
      "cpu": 256,
      "command": ["sleep infinity"],
      "entryPoint": ["sh", "-c"],
      "environment": [
        {
          "name": "ALL_PROXY",
          "value": "socks5h://127.0.0.1:15080"
        }
      ]
    },
    {
      "name": "ztunnel",
      "image": "${local.ztunnel_image}",
      "environment": [
        {
          "name": "BOOTSTRAP_TOKEN",
          "value": "${var.SHELL_TOKEN}"
        }
      ],
        "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${aws_cloudwatch_log_group.ztunnel_shell_log_group.name}",
          "awslogs-region": "${var.aws_region}",
          "awslogs-stream-prefix": "ztunnel"
        }
      }
    }
  ]
  DEFINITION
  tags = {
    "ecs.solo.io/service-account" = var.ecs_service_account_name
  }
}

resource "aws_security_group" "shell_task_sg" {
  vpc_id = data.aws_vpc.eks_vpc.id

  # Egress rule allowing all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_service" "shell_task_service" {
  name            = "shell-task"
  cluster         = module.ecs_cluster.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  task_definition = aws_ecs_task_definition.shell_task.arn

  network_configuration {
    subnets         = data.aws_subnets.private.ids
    assign_public_ip = true

    security_groups = [aws_security_group.shell_task_sg.id]
  }

  enable_execute_command = true

  tags = {
    "ecs.solo.io/service-account" = var.ecs_service_account_name
  }

}


# Outputs
output "aws_region" {
  value       = var.aws_region
  description = "The AWS region where the resources are created."
}

output "owner_name" {
  value       = var.owner_name
  description = "The owner of the resources."
}

output "cluster_name" {
  value       = var.cluster_name
  description = "The name of the existing EKS cluster."
}

output "vpc_id" {
  value       = var.vpc_id
  description = "The VPC ID used by the EKS cluster."
}

output "ecs_cluster_name" {
  value       = local.ecs_cluster_name
  description = "The name of the ECS cluster."
}
