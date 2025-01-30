# ECS Ambient Integration - Demo

This guide provides detailed instructions to deploy an **early access version** of ECS Ambient integration. Please note that this setup is being continuously improved based on feedback from users and the broader community. As the product evolves, it will be enhanced and refined into an even better version.

The setup has been validated for this phase, and following these steps should result in a successful integration. However, please be aware that changes may occur as we gather feedback and make improvements.

In addition to this GitHub repository, it is important to know that you would need to **contact Solo.io** to obtain the early access `istioctl` binaries and private repository access to the container images.

## Variables to Configure

The following environment variables are needed to configure your EKS cluster. These values specify the AWS region, cluster owner, EKS version, cluster name, number of nodes, and node types. Be sure to adjust these based on your needs.

```bash
export AWS_REGION=us-east-1        # The AWS region where the cluster will be deployed
export OWNER_NAME=$(whoami)        # The name of the cluster owner (auto-fills with your username)
export EKS_VERSION=1.31            # Version of EKS to be used for the cluster
export CLUSTER_NAME=ambient-ecs    # Name of the cluster
export NUMBER_NODES=2              # The number of nodes in your EKS cluster
export NODE_TYPE="t2.medium"       # The instance type for the nodes in the EKS cluster
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

Gateway API is a new set of resources to manage service traffic in a Kubernetes-native way. Here, we're installing the most recent (as of January 2025) version of the Kubernetes Gateway API CRDs, which will be used by Istio for ingress.

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
```

For more details, refer to the official [Gateway API documentation](https://gateway-api.sigs.k8s.io/guides/) and the Istio [documentation](https://istio.io/latest/docs/tasks/traffic-management/ingress/gateway-api/).

## Obtain the most recent binary

To obtain the appropriate **early access** version of istioctl, which includes support for ECS, please provide Solo.io with your operating system (OS) and architecture (ARCH) to receive the correct binary archive.

Once you've received the appropriate `istioctl` archive, you'll need to extract the contents and clean up by deleting the archive file. The following commands will help you achieve that:

```bash
# Set the version recommended by Solo.io

export ISTIO_VERSION=<solo provided version>

# Set the OS and ARCH variables based on your environment

export OS=<your OS>               # Can be linux, darwin, or windows
export ARCH=<your Architecture>   # Can be amd64, arm64, or armv7

# Extract the contents
tar -xzf istioctl-$ISTIO_VERSION-solo-$OS-$ARCH.tar.gz

# Delete the archive file
rm istioctl-$ISTIO_VERSION-solo-$OS-$ARCH.tar.gz
```

Confirm istioctl version:

```bash
./istioctl version
```

the expected output:

```output
Istio is not present in the cluster: no running Istio pods in namespace "istio-system"
client version: 1.2<version should match ISTIO_VERSION>
```

### Install Istio in `Ambient` Mode with ECS Cluster Integration

This command installs Istio in Ambient mode with all the required settings for integrating with an ECS cluster. In addition to enabling Ambient mode, it also includes the **ECS cluster name**, which for this demo is based on the EKS cluster name defined earlier. By adding the ECS cluster information, the Istio control plane can automatically discover services running in ECS tasks, allowing for seamless service discovery across both Kubernetes and ECS.

Please note that the snippet currently points to a **private image repository** for Istio components, which is provided by Solo.io as explained earlier. Ensure you have access to this private repository or modify the image source to suit your environment by using the following command:

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

Expected output:

```output
        |\
        | \
        |  \
        |   \
      /||    \
     / ||     \
    /  ||      \
   /   ||       \
  /    ||        \
 /     ||         \
/______||__________\
____________________
  \__       _____/
     \_____/

✔ Istio core installed ⛵️
✔ Istiod installed 🧠
✔ CNI installed 🪢
✔ Ztunnel installed 🔒
✔ Installation complete
The ambient profile has been installed successfully, enjoy Istio without sidecars!
```

This configuration allows the Istio control plane to interact with both Kubernetes and ECS services.

### Explanation of Parameters:

- `profile=ambient`: Specifies that we want to install Istio in Ambient mode.
- `meshConfig.accessLogFile`: Logs all traffic for debugging purposes.
- `dnsCapture=true`: Ensures that DNS traffic is captured by Ambient ztunnels.

By now EKS Cluster with Isto in Ambient mode is installed and ready to be used.

![EKS Cluster with Istio in Ambient Mode](img/state-1.png)

## Create the ECS Task Role

Following AWS best security practices and to avoid manual BOOTSTRAP token exchanged, an ECS Task Role will be created in AWS IAM, which `istioctl` will use. If the role already exists, the script will proceed without making changes. If the role does not exist, the script will create it.

Additionally, this script ensures the ECS Task has an **execution role** allowing it to write to **CloudWatch Logs**. This role is necessary for ECS tasks to send logs to CloudWatch.

The script will check if the ECS Task Role exists in your AWS account and if the Role is not present, it will:
  - Create an IAM policy with the necessary permissions.
  - Create an IAM role.
  - Assign the newly created permissions to the newly created IAM role.

Additionally the script will **Export the ARNs of the roles (whether created or pre-existing)** as environment variables for use in the subsequent steps.

### How to Run:

Before proceeding with the next steps, you must **source** the script. This will check for the necessary roles, create them if they don't exist, and **export the role ARNs** to environment variables that are used in the following steps.

```bash
source scripts/build/create-iam.sh
```

Expected output:

```output
$ source scripts/build/create-iam.sh
Creating task role...
TASK_ROLE_ARN exported: arn:aws:iam::835335437537:role/ecs/ambient/eks-ecs-task-role
Creating task policy...
TASK_POLICY_ARN exported: arn:aws:iam::835335437537:policy/ecs/ambient/eks-ecs-task-policy
Creating execution role...
EXECUTION_ROLE_ARN exported: arn:aws:iam::835335437537:role/ecs/ambient/ecs-task-execution-role
Task role and execution role are ready.
```

## Create Namespace for ECS

In this step, we create a new namespace in Kubernetes called `ecs`, which will be used to store configuration objects related to ECS workloads (such as `WorkloadEntries` and `ServiceEntries`).

```bash
export ECS_NS=ecs  # This namespace is required for the demo to work
export ECS_SERVICE_ACCOUNT_NAME=demo  # This service account name is required for the demo

kubectl create ns ${ECS_NS}
kubectl label namespace ${ECS_NS} istio.io/dataplane-mode=ambient
kubectl create sa $ECS_SERVICE_ACCOUNT_NAME -n $ECS_NS
kubectl -n $ECS_NS annotate sa $ECS_SERVICE_ACCOUNT_NAME ecs.solo.io/role-arn=$(echo $TASK_ROLE_ARN | sed 's/\/ecs\/ambient//') --overwrite
```

## Enable Istiod to Accept Calls from ECS

In this step, we configure `istiod` to securely accept communication from the ECS cluster. This ensures that ztunnels in ECS can bootstrap workloads with the necessary security measures in place.

```bash
kubectl apply -f manifests/east-west-cp.yaml
```

![EKS Cluster with Istio CP exposed and ECS Namespace](img/state-2.png)

## Deploy ECS Task

A shell script is used to deploy ECS tasks. It will create two tasks - one will be used to initiate the calls and another one to receive the calls. The script will create the ECS tasks in `ecs-demo` cluster.

```bash
scripts/build/deploy-ecs-tasks.sh
```

Expected output:

```output
$ scripts/build/deploy-ecs-tasks.sh
Registering task definition for shell-task-definition.json...
Task definition shell-task-definition.json registered successfully.
Registering task definition for echo-task-definition.json...
Task definition echo-task-definition.json registered successfully.
All task definitions registered successfully.
ecs_vpc_id: vpc-048ea4882f423f0c1
Private Subnet IDs: subnet-00989435327e326a9,subnet-0952e8295616c404c,subnet-00a002d0f2f2f9a70
Security Group IDs: sg-06c232b01eb75663d
ECS services script is completed.
```

**NOTE** The current ECS task definition for `shell` task sets the environment variable `ALL_PROXY=socks5h://127.0.0.1:15080`. This configuration ensures that all traffic is routed through the local SOCKS5 proxy at port 15080. As a result, all communication from the application or service running as an ECS Task is captured by the Istio Ambient (`ztunnel` component).

## Add ECS Service to Istio

This can be done with istioctl:

```bash
./istioctl ecs add-service shell-task --cluster ecs-$CLUSTER_NAME --namespace $ECS_NS
./istioctl ecs add-service echo-service --cluster ecs-$CLUSTER_NAME --namespace $ECS_NS
```

the expected output:

```output
 Generating a bootstrap token for ecs/default...
• Fetched Istiod Root Cert
• Fetching Istiod URL...
  • Service "eastwest" provides Istiod access on port 15012
• Fetching Istiod URL (https://ae9f1c4f873dc465a9edd7b81d09c40a-1856501301.us-west-1.elb.amazonaws.com:15012)
• Workload is authorized to run as role "arn:aws:iam::835335437537:role/ecs/ambient/eks-ecs-task-role"
• Created task definition arn:aws:ecs:us-west-1:835335437537:task-definition/shell-task-definition:37
• Successfully enrolled service "shell-task" (arn:aws:ecs:us-west-1:835335437537:service/ecs-demo-ztunnel-0/shell-task) to the mesh
• Generating a bootstrap token for ecs/default...
• Fetched Istiod Root Cert
• Fetching Istiod URL...
  • Service "eastwest" provides Istiod access on port 15012
• Fetching Istiod URL (https://ae9f1c4f873dc465a9edd7b81d09c40a-1856501301.us-west-1.elb.amazonaws.com:15012)
• Workload is authorized to run as role "arn:aws:iam::835335437537:role/ecs/ambient/eks-ecs-task-role"
• Created task definition arn:aws:ecs:us-west-1:835335437537:task-definition/echo-service-definition:19
• Successfully enrolled service "echo-service" (arn:aws:ecs:us-west-1:835335437537:service/ecs-demo-ztunnel-0/echo-service) to the mesh
```

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

Confirm communication between an EKS pod and an EKS service:

```bash
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl eks-echo:8080
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
```

Test communication from an EKS pod to an ECS service via ztunnel

```bash
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl echo-service.ecs.local:8080
```

Expected output:

```output
ServiceVersion=
ServicePort=8080
Host=echo-service.ecs.local:8080
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

## Run the Test Script

After setting up the security groups, run the test script to demonstrate the communication between ECS and EKS workloads.

The test script reads a list of curl commands from a file (in this case, tests/ecs-test-commands.txt) and executes each command on the ECS container using the AWS ecs execute-command functionality. All traffic between ECS and EKS workloads is secured with mTLS, ensuring that it is encrypted, verified, and routed through the Istio ztunnel.

Run the Test Script: The script takes the file as input and executes each command sequentially on the ECS task.

```bash
scripts/test/call-from-ecs.sh tests/ecs-test-commands.txt
```

Expected output:

```output
$ scripts/test/call-from-ecs.sh tests/ecs-test-commands.txt
Cluster name not provided, trying to connect to the cluster ecs-demo-ztunnel-0
Using Task ID: 7121f914d8864596b14622ae1be8da61
-----
Running command: curl eks-echo.default:8080
ServiceVersion=
ServicePort=8080
Host=eks-echo.default:8080
URL=/
Method=GET
Proto=HTTP/1.1
IP=192.168.123.30
RequestHeader=Accept:*/*
RequestHeader=User-Agent:curl/8.11.1
Hostname=eks-echo-6c84bd6f6-97pls
-----
Running command: curl echo-service.ecs.local:8080
ServiceVersion=
ServicePort=8080
Host=echo-service.ecs.local:8080
URL=/
Method=GET
Proto=HTTP/1.1
IP=192.168.121.25
RequestHeader=Accept:*/*
RequestHeader=User-Agent:curl/8.11.1
RequestHeader=X-Forwarded-Proto:http
RequestHeader=X-Request-Id:995cb7ef-598b-4866-8ac1-fe844a22d1e1
Hostname=ip-192-168-121-25.us-west-1.compute.internal
-----
Running command: curl -I httpbin.org
HTTP/1.1 200 OK
Date: Wed, 29 Jan 2025 22:16:50 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 9593
Connection: keep-alive
Server: gunicorn/19.9.0
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

## Advanced Use-Cases

For testing connectivity from ECS, we will use the `call-from-ecs.sh` script. This script finds the ECS tasks running the `shell` container in the ECS cluster created by Terraform and executes `curl` commands provided in a text file. The script automates the process of sending requests to different services in the cluster, allowing you to validate connectivity and communication based on the specified parameters.

### Layer 4 Policies for EKS Workloads

In this section, you'll apply a **Deny All** L4 policy to EKS workloads and test various communications between ECS and EKS tasks.

First, apply the Deny All policy to block all traffic to EKS workloads:

```bash
kubectl apply -f manifests/eks-deny.yaml
```

After applying the policy, test the following scenarios:

- **ECS to ECS communication**: This should **succeed** since the policy only applies to EKS workloads.

```bash
scripts/test/call-from-ecs.sh tests/ecs-to-ecs.txt
```

- **ECS to EKS communication**: This should be **blocked** by the L4 policy.

```bash
scripts/test/call-from-ecs.sh tests/ecs-to-eks.txt
```

Finally, test if **EKS to ECS communication** still **succeeds** as no policy is blocking it:

```bash
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl echo-service.ecs.local:8080
```

### Layer 4 Policies for ECS Workloads

Next, let's test a similar policy for ECS workloads.

First, remove the previous policy to ensure cleaner testing and apply a similar **Deny All** policy for ECS:

```bash
kubectl delete -n default authorizationpolicies eks-echo-deny
kubectl apply -f manifests/ecs-deny.yaml
```

Test the following scenarios:

- **ECS to ECS communication**: This should be **denied** by the freshly applied policy.

```bash
scripts/test/call-from-ecs.sh tests/ecs-to-ecs.txt
```

- **ECS to EKS communication**: This should now be **allowed** since no L4 policy is applied to EKS workloads.

```bash
scripts/test/call-from-ecs.sh tests/ecs-to-eks.txt
```

Finally, test if **EKS to ECS communication** is now **blocked** by the policy for ECS workloads:

```bash
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl echo-service.ecs.local:8080
```

### Layer 7 Policies

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
scripts/test/call-from-ecs.sh tests/ecs-to-ecs-post.txt
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl -X POST echo-service.ecs.local:8080
```

- **GET requests**: These will be **denied** with `RBAC: access denied`.

```bash
scripts/test/call-from-ecs.sh tests/ecs-to-ecs-get.txt
kubectl exec -it $(kubectl get pods -l app=eks-shell -o jsonpath="{.items[0].metadata.name}") -- curl -X GET echo-service.ecs.local:8080
```

To reset the environment, delete the L7 policy:

```bash
kubectl delete -f manifests/post-only-allow.yaml
```

# Cleanup

To clean up the resources created during this demo, you can use the following commands:

First run the cleanup script for the ECS artifacts:

```bash
scripts/cleanup/ecs-cleanup.sh
```

use separate script to delete IAM roles and policies:

```bash
scripts/cleanup/iam-cleanup.sh
```

Finally, delete the EKS cluster:

```bash
eksctl delete cluster --name ${CLUSTER_NAME} --region ${AWS_REGION}
```

If you encounter any issues during testing, please reach out to your Solo.io representative for assistance.
