#  Kubernetes (EKS) Security Audit Access Requirements

To effectively perform a comprehensive security audit of your AWS EKS clusters located within private VPCs, the following access, roles, and infrastructure prerequisites must be established:

### 1. Jump Box Setup

We recommend provisioning a dedicated jump box (bastion host) within a private subnet inside your VPC. This approach significantly minimizes external exposure.

**Specifications:**
* **OS**: Amazon Linux 2 or Ubuntu LTS
* **Instance Type**: t3.medium or equivalent
* **Subnet Placement**: Private subnet with necessary route table entries for EKS cluster communication
* **Security Group Requirements**:
* Allow inbound SSH (TCP 22) or AWS SSM access (via AWS Systems Manager endpoints)
* Allow outbound communication to Kubernetes API Server endpoints and worker node subnets (typically TCP 443 and any necessary application ports)

### 2. Access Methods

Secure and controlled access to the jump box can be facilitated through:
* **SSH**: Secure Shell access using authorized SSH keys (public key authentication required).
* **AWS SSM Session Manager**: Recommended for environments requiring stricter security controls and compliance.

**Preferred Method**: AWS SSM Session Manager (no inbound ports required).

### 3. IAM Role and Permissions

The jump box or user session will require an IAM role with adequate permissions to interact with AWS and Kubernetes resources:
* eks:DescribeCluster
* eks:ListClusters
* eks:AccessKubernetesApi
* AWS CloudWatch Logs read-only (if applicable for audit)
* AWS CloudTrail read-only (for audit log access)
* EC2 read-only (to enumerate infrastructure)

### 4. Kubernetes Access

To assess your Kubernetes cluster effectively, we require access via:
* **Kubernetes RBAC Role**:
* view or equivalent cluster-level read-only access (ClusterRoleBinding)
* Access to security-sensitive resources such as:
* pods, services, deployments, daemonsets, statefulsets
* configmaps, secrets (if allowed per scope)
* nodes, namespaces, roles, rolebindings, clusterroles, clusterrolebindings

A specific audit role (e.g., cluster-audit-read-only) with clearly scoped permissions is strongly recommended.

### 5. Authentication to the Cluster

The following authentication methods are acceptable for accessing the Kubernetes cluster:
* **Kubeconfig File**: (Recommended) Securely provide a kubeconfig file with appropriate cluster credentials and context.
* **IAM Authentication (aws-iam-authenticator)**: If IAM roles are used, ensure the provided role has EKS cluster access.
* **Temporary Token Authentication**: Secure token provisioning via automated workflows or credential services.

Typically, a kubeconfig file with limited, audit-specific permissions is the easiest and most secure method for authentication.

### 6. Connectivity Requirements

From the jump box, connectivity must be explicitly allowed to:
* Kubernetes API endpoints (typically TCP port 443)
* Worker node IP addresses (to test node security and configuration)
* AWS API endpoints (for necessary AWS enumeration and information gathering)

### 7. Logging and Audit

We strongly encourage enabling detailed logging for audit purposes:
* **AWS CloudTrail** logging of all EKS API requests
* **AWS CloudWatch Logs** or **Container Insights** enabled for real-time and historical log access
* Kubernetes audit logging enabled and accessible (recommended)

### 8. Security Controls & Compliance
* Ensure MFA (Multi-factor Authentication) is enabled for AWS access
* Temporary access credentials with specified expiration are recommended
* All access granted for audit purposes should be documented and periodically reviewed.

### Next Steps

To facilitate rapid onboarding, please:
	1.	Provision the jump box and assign required IAM permissions.
	2.	Configure Kubernetes RBAC roles and permissions as outlined.
	3.	Schedule an access verification session before commencing the full audit.

We appreciate your cooperation and proactive measures to ensure a secure and efficient auditing process.