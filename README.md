# ECS Ambient Prototype Setup - Step-by-Step Instructions

This guide provides detailed instructions to deploy an **alpha prototype** of ECS Ambient integration. Please note that this setup is still in the **alpha phase**, and will evolve based on feedback from internal teams, external users, and the broader community. As the prototype progresses, it will continue to be refined and shaped into a finalized product.

The setup has been validated for this phase, and following these steps should result in a successful integration. However, please be aware that changes may occur as we gather feedback and make improvements.

In addition to this GitHub repository, there are two other locations where important artifacts can be found:

- Contact Solo.io to obtain the istioctl binaries.
- Docker Hub hosts the alpha images.

## Variables to Configure

The following environment variables are needed to configure your EKS cluster. These values specify the AWS region, owner, EKS version, cluster name, number of nodes, and node types. Be sure to adjust these based on your needs.

```bash
export AWS_REGION=us-west-1        # The AWS region where the cluster will be deployed
export OWNER_NAME=$(whoami)        # The name of the cluster owner (auto-fills with your username)
export EKS_VERSION=1.31            # Version of EKS to be used for the cluster
export CLUSTER_NAME=demo-ztunnel-0 # Name of the cluster
export NUMBER_NODES=2              # The number of nodes in your EKS cluster
export NODE_TYPE="t2.medium"      # The instance type for the nodes in the EKS cluster
```

## Create Cluster with `eksctl` Using Inline YAML

Rather than creating a configuration file on your filesystem, you can pass the configuration directly as an inline YAML block. This approach saves time and allows you to define your cluster parameters in a single command.

```bash
eksctl create cluster --config-file - << EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_REGION}
  version: "${EKS_VERSION}"
  tags:
    owner: ${OWNER_NAME}

addons:
  - name: vpc-cni                            # Addon to enable networking for the cluster
  - name: eks-pod-identity-agent             # Enables pod identity management for ECS workloads

iam:
  withOIDC: true                             # Required to use IAM roles for service accounts
  podIdentityAssociations:
    - namespace: istio-system                # Namespace for Istio control plane
      serviceAccountName: istiod             # Istio's control plane service account
      roleName: istiod-eks-ecs-${CLUSTER_NAME}  # Custom IAM role for Istio control plane with ECS access
      permissionPolicyARNs: [arn:aws:iam::aws:policy/AmazonECS_FullAccess]

managedNodeGroups:
  - name: managed-nodes
    instanceType: ${NODE_TYPE}               # Instance type defined in variables
    desiredCapacity: ${NUMBER_NODES}         # Number of nodes to create
    privateNetworking: true                  # Ensure nodes are launched within private subnets
    updateConfig:
      maxUnavailable: 2                      # Number of nodes that can be updated at the same time
EOF
```

## Deploy Kubernetes Gateway API CRDs

Gateway API is a new set of resources to manage service traffic in a Kubernetes-native way. Here, we're installing the experimental version of the Gateway API, which will be used by Istio for ingress.

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.1.0/experimental-install.yaml
```

For more details, refer to the official [Gateway API documentation](https://gateway-api.sigs.k8s.io/guides/) and the Istio [documentation](https://istio.io/latest/docs/tasks/traffic-management/ingress/gateway-api/).

## Obtain the most recent binary
To obtain the appropriate alpha version of istioctl, which includes support for ECS, please provide Solo.io with your operating system (OS) and architecture (ARCH) to receive the correct binary archive.

Once you've received the appropriate `istioctl` archive, you'll need to extract the contents and clean up by deleting the archive file. The following commands will help you achieve that:


```bash
# Set the version recommended by Solo.io 

export ISTIO_VERSION=<solo provided version>

# Set the OS and ARCH variables based on your environment

export OS=<your OS>               # Can be linux, darwin, or windows
export ARCH=<your Architecture>   # Can be amd64, arm64, or armv7

# Extract the contents
tar -xzf istioctl-$ISTIO_VERSION-$OS-$ARCH.tar.gz

# Delete the archive file
rm istioctl-$ISTIO_VERSION-$OS-$ARCH.tar.gz
```

Confirm istioctl version:

```bash
./istioctl version
```

the expected output:

```output
Istio is not present in the cluster: no running Istio pods in namespace "istio-system"
client version: 1.2<version should match ISTIO_VERSION> details

### Install Istio in `Ambient` Mode with ECS Cluster Integration

This command installs Istio in Ambient mode with all the required settings for integrating with an ECS cluster. In addition to enabling Ambient mode, it also includes the **ECS cluster name**, which for this demo is based on the EKS cluster name defined earlier. By adding the ECS cluster information, the Istio control plane can automatically discover services running in ECS tasks, allowing for seamless service discovery across both Kubernetes and ECS.

Please note that the snippet currently points to a **private image repository** for Istio components, so ensure you have access to the private repository or modify the image source as needed for your environment By using the following command:

```bash
export HUB=<repo provided by Solo.io>
```

Now you're ready to install Istio in Ambient mode with ECS cluster integration:

```bash
cat <<EOF | ./istioctl install -y -f -
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  profile: ambient
  # Make debugging easier
  meshConfig:
    accessLogFile: /dev/stdout
  values:
    global:
      hub: ${HUB}
    ztunnel:
    cni:
      # Enable DNS proxy
      ambient:
        dnsCapture: true
    platforms:
      ecs:
        cluster: ecs-${CLUSTER_NAME}
    pilot:
      env:
        # Required for full DNS proxying support
        PILOT_ENABLE_IP_AUTOALLOCATE: "true"
        # Required for some of the GW usage we are doing
        PILOT_ENABLE_ALPHA_GATEWAY_API: "true"
        # Required for our authentication to Istiod
        REQUIRE_3P_TOKEN: "false"
EOF
```

This configuration allows the Istio control plane to interact with both Kubernetes and ECS services.


### Explanation of Parameters:
- `profile=ambient`: Specifies that we want to install Istio in Ambient mode.
- `meshConfig.accessLogFile`: Logs all traffic for debugging purposes.
- `dnsCapture=true`: Ensures that DNS traffic is captured by Ambient ztunnels.

## Create the ECS Task Role

To keep the AUTH key out of the BOOTSTRAP token (below), we need to create an ECS Task Role in AWS, which `istioctl` will use. If the role already exists, the script will proceed without making changes. If the role does not exist, the script will create it.

Additionally, this script ensures the ECS Task has an **execution role** allowing it to write to **CloudWatch Logs**. This role is necessary for ECS tasks to send logs to CloudWatch.

The script will:
1. Check if the ECS Task Role exists in your AWS account.
2. Create the role if it doesn't exist, with the necessary permissions to write to CloudWatch.
3. **Export the ARNs of the roles (whether created or pre-existing)** as environment variables for use in the subsequent steps.

### How to Run:
Before proceeding with the next steps, you must **source** the script. This will check for the necessary roles, create them if they don't exist, and **export the role ARNs** to environment variables that are used in the following steps.

```bash
source scripts/create-ecs-role.sh
```

## Create Namespace for ECS

In this step, we create a new namespace in Kubernetes called `ecs`, which will be used to store configuration objects related to ECS workloads (such as `WorkloadEntries` and `ServiceEntries`). 

For this **demo**, the namespace and service account names are predefined to ensure consistency. You should use the following names for the demo to work correctly. However, in a real deployment, both the namespace and service account names can be customized to fit your environment.

```bash
export ECS_NS=ecs  # This namespace is required for the demo to work
export ECS_SERVICE_ACCOUNT_NAME=httpbin  # This service account name is required for the demo

kubectl create ns ${ECS_NS}
kubectl label namespace ${ECS_NS} istio.io/dataplane-mode=ambient
kubectl create sa $ECS_SERVICE_ACCOUNT_NAME -n $ECS_NS
kubectl -n $ECS_NS annotate sa $ECS_SERVICE_ACCOUNT_NAME ecs.solo.io/role-arn=$(echo $TASK_ROLE_ARN | sed 's/\/ecs\/ambient//') --overwrite
```

Note:
- For the purposes of this demo, the namespace (ECS_NS) is set to ecs and the service account (ECS_SERVICE_ACCOUNT_NAME) is set to httpbin.
  You should not change these values when running the demo, as doing so will cause the demo to fail.
- In a real customer deployment, these names can be customized to meet your specific requirements.

## Enable Istiod to Accept Calls from ECS

In this step, we configure `istiod` to securely accept communication from the ECS cluster. This ensures that ztunnels in ECS can bootstrap workloads with the necessary security measures in place.

```bash
kubectl apply -f manifests/east-west-cp.yaml
```

## Generate and Validate Bootstrap Tokens for ECS Workloads

Next, generate bootstrap tokens for ECS workloads to securely communicate with the `Istiod` control plane. These tokens ensure that ECS workloads can authenticate and interact with the control plane securely.


```bash
export TF_VAR_ECHO_TOKEN=`./istioctl bootstrap \
    --service-account $ECS_SERVICE_ACCOUNT_NAME \
    --namespace $ECS_NS \
    --platform ecs`
export TF_VAR_SHELL_TOKEN="${TF_VAR_ECHO_TOKEN}"
```
Upon running the command, you should see output similar to the following:
```output
• Generating a bootstrap token for ecs/httpbin...
• Fetched Istiod Root Cert
• Fetched Istio network (eks)
• Fetching Istiod URL...
  • Service "eastwest-istio-eastwest" provides Istiod access on port 15012
• Fetching Istiod URL (https://add0bbbc68eb341a79b162086af38593-1878546887.us-west-2.elb.amazonaws.com:15012)
• Workload is authorized to run as role "arn:aws:iam::835335437537:role/eks-ecs-task-role"
```

## Deploy ECS Task

To deploy ECS tasks using Terraform, set the following environment variables, which are required for the task deployment:

```bash
export TF_VAR_aws_region="$AWS_REGION"
export TF_VAR_owner_name="$OWNER_NAME"
export TF_VAR_cluster_name="$CLUSTER_NAME"
export TF_VAR_istio_version="$ISTIO_VERSION"
export TF_VAR_istio_repo="$HUB"
export TF_VAR_ecs_cluster_name="ecs-$CLUSTER_NAME"
export TF_VAR_ecs_task_role_arn="$TASK_ROLE_ARN"
export TF_VAR_ecs_execution_role_arn="$TASK_ROLE_ARN"
export TF_VAR_ecs_service_account_name=$ECS_SERVICE_ACCOUNT_NAME

export TF_VAR_vpc_id=$(aws eks describe-cluster \
  --name "$CLUSTER_NAME" \
  --region "$AWS_REGION" \
  --query 'cluster.resourcesVpcConfig.vpcId' \
  --output text)

echo "VPC ID: $TF_VAR_vpc_id"
```

After setting the environment variables, deploy ECS tasks (echo and shell services) using Terraform:

```bash
terraform -chdir=./tf init
terraform -chdir=./tf apply --auto-approve
```

__NOTE__ The current Terraform definition sets the environment variable `ALL_PROXY=socks5h://127.0.0.1:15080`. This configuration ensures that all traffic is routed through the local SOCKS5 proxy at port 15080. As a result, all communication from the application or service running as an ECS Task is captured by the `ztunnel`.

## Deploy Test Pods in the EKS Cluster
To test the setup, deploy shell and echo applications in the EKS cluster to ensure everything is functioning properly:

```bash
# Label the default namespace with ambient mode
kubectl label namespace default istio.io/dataplane-mode=ambient

# Deploy the test applications
kubectl apply -f manifests/eks-echo.yaml
kubectl apply -f manifests/eks-shell.yaml
```

These commands will deploy the test pods in your EKS cluster to verify that the integration between ECS and Istio is working correctly.

## Test EKS to ECS Communication

In this step, you will verify that EKS pods can communicate with ECS services 
by making HTTP requests from an EKS pod to services running both in EKS and ECS.
This confirms that the setup between EKS and ECS is functioning correctly.

Verify that EKS pods can communicate with ECS services:

```bash
# Test communication from an EKS pod to an EKS service
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl eks-echo:8080

# Test communication from an EKS pod to an ECS service via ztunnel
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl echo-ztunnel.ecs.local:8080
```

Expected output:

```output
ServiceVersion=
ServicePort=8080
Host=eks-echo:8080
URL=/
Method=GET
Proto=HTTP/1.1
IP=192.168.116.225
RequestHeader=Accept:*/*
RequestHeader=User-Agent:curl/8.10.1
Hostname=eks-echo-5484d5bd99-hlk6w
ServiceVersion=
ServicePort=8080
Host=echo-ztunnel.ecs.local:8080
URL=/
Method=GET
Proto=HTTP/1.1
IP=192.168.79.89
RequestHeader=Accept:*/*
RequestHeader=User-Agent:curl/8.10.1
Hostname=ip-192-168-79-89.us-west-2.compute.internal
```

## Test ECS to EKS Communication

To test connectivity from ECS to EKS, you first need to grant access to the EKS services from ECS by modifying the security groups. Then, you can run a script to verify communication between ECS and EKS workloads.

### Grant Access to EKS Services from ECS

For this demo, the security group settings are opened wide to simplify testing and ensure connectivity between ECS and EKS workloads. However, in a real-world deployment, **security groups should be configured more tightly** to restrict access based on specific CIDR ranges, protocols, and ports. Limiting access helps to maintain security and prevent unwanted traffic between ECS and EKS environments.

Modify the security groups to allow ingress from ECS tasks:


```bash
# Get the security group ID for the EKS cluster
SG_ID=$(aws ec2 describe-security-groups \
  --filters Name=vpc-id,Values=$TF_VAR_vpc_id \
           Name=group-name,Values='eks-cluster-sg*' \
  --query 'SecurityGroups[0].GroupId' \
  --output text)

# Authorize ingress for the security group (allow all traffic from any IP, can be restricted later)
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol -1 \
  --cidr 0.0.0.0/0 \
  --no-cli-pager
```

## Run the Test Script

After setting up the security groups, run the test script to demonstrate the communication between ECS and EKS workloads.

The test script reads a list of curl commands from a file (in this case, tests/ecs-test-commands.txt) and executes each command on the ECS container using the AWS ecs execute-command functionality. All traffic between ECS and EKS workloads is secured with mTLS, ensuring that it is encrypted, verified, and routed through the Istio ztunnel.


Run the Test Script: The script takes the file as input and executes each command sequentially on the ECS task.
```bash
scripts/call-from-ecs.sh tests/ecs-test-commands.txt
```


Expected output:
```output
$ scripts/call-from-ecs.sh tests/ecs-test-commands.txt
Cluster name not provided, trying to connect to the cluster ecs-demo-ztunnel-0...
Using Task ID: d29168b7d25c4184994242ac679e5968
-----
Running command: curl eks-echo.default:8080
ServiceVersion=
ServicePort=8080
Host=eks-echo.default:8080
URL=/
Method=GET
Proto=HTTP/1.1
IP=192.168.102.16
RequestHeader=Accept:*/*
RequestHeader=User-Agent:curl/8.10.1
Hostname=eks-echo-5484d5bd99-hlk6w
-----
Running command: curl echo-ztunnel.ecs.local:8080
ServiceVersion=
ServicePort=8080
Host=echo-ztunnel.ecs.local:8080
URL=/
Method=GET
Proto=HTTP/1.1
IP=192.168.79.89
RequestHeader=Accept:*/*
RequestHeader=User-Agent:curl/8.10.1
Hostname=ip-192-168-79-89.us-west-2.compute.internal
-----
Running command: curl -I httpbin.org
HTTP/1.1 200 OK
Date: Wed, 02 Oct 2024 20:26:22 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 9593
Connection: keep-alive
Server: gunicorn/19.9.0
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```


## Advanced Use-Cases

For testing connectivity from ECS, we will use the `call-from-ecs.sh` script. This script finds the ECS tasks running the `shell` container in the ECS cluster created by Terraform and executes `curl` commands provided in a text file. The script automates the process of sending requests to different services in the cluster, allowing you to validate connectivity and communication based on the specified parameters.

### Test L4 Policy

In this section, you'll apply a **Deny All** L4 policy to EKS workloads and test various communications between ECS and EKS tasks.

First, apply the Deny All policy to block all traffic to EKS workloads:

```bash
kubectl apply -f manifests/eks-deny.yaml
```

After applying the policy, test the following scenarios:

- **ECS to ECS communication**: This should **succeed** since the policy only applies to EKS workloads.

```bash
scripts/call-from-ecs.sh tests/ecs-to-ecs.txt
```

- **ECS to EKS communication**: This should be **blocked** by the L4 policy.

```bash
scripts/call-from-ecs.sh tests/ecs-to-eks.txt
```

Finally, test if **EKS to ECS communication** still **succeeds** as no policy is blocking it:

```bash
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl echo-ztunnel.ecs.local:8080
```

### Test ECS L4 Policy
Next, let's test a similar policy for ECS workloads.

First, remove the previous policy to ensure cleaner testing and apply a similar **Deny All** policy for ECS:

```bash
kubectl delete -n default authorizationpolicies eks-echo-deny
kubectl apply -f manifests/ecs-deny.yaml
```

Test the following scenarios:

- **ECS to ECS communication**: This should be **denied** by the freshly applied policy.

```bash
scripts/call-from-ecs.sh tests/ecs-to-ecs.txt
```

- **ECS to EKS communication**: This should now be **allowed** since no L4 policy is applied to EKS workloads.

```bash
scripts/call-from-ecs.sh tests/ecs-to-eks.txt
```

Finally, test if **EKS to ECS communication** is now **blocked** by the policy for ECS workloads:

```bash
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl echo-ztunnel.ecs.local:8080
```

### Test L7 Policy

For clarity, remove the previous policy:

```bash
kubectl delete -n ecs authorizationpolicies ecs-deny-all
```

Now, enable the Waypoint proxy in the ECS namespace:

```bash
./istioctl waypoint apply -n ecs --enroll-namespace
``` 

Apply an L7 policy to allow only **POST** operations:

```bash
kubectl apply -f manifests/post-only-allow.yaml
```

Test the following scenarios:

- **POST requests**: These should be **allowed**.
```bash
scripts/call-from-ecs.sh tests/ecs-to-ecs-post.txt
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl -X POST echo-ztunnel.ecs.local:8080
```

- **GET requests**: These will be **denied** with `RBAC: access denied`.
```bash
scripts/call-from-ecs.sh tests/ecs-to-ecs-get.txt
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl -X GET echo-ztunnel.ecs.local:8080
```

If you encounter any issues during testing, please reach out to petr.mcallister@solo.io.