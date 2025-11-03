
# Amazon EKS Security Audit Checklist

A comprehensive, generic audit framework to assess the security posture of an Amazon Elastic Kubernetes Service (EKS) environment.  
Use this checklist during periodic reviews, compliance audits (HIPAA, HITRUST, CIS, ISO 27001), or pre-production validation.

---

## 🧱 1. Network & VPC Configuration

### VPC & Subnets
- [ ] Confirm **private subnets** are used for worker nodes and control plane ENIs.  
- [ ] Verify **no Internet Gateway (IGW)** attached to private subnets unless explicitly required.  
- [ ] Validate **route tables**:
  - [ ] No `0.0.0.0/0` routes pointing to IGW or NAT for sensitive workloads.
  - [ ] Routes to **VPC endpoints** exist for S3, ECR, CloudWatch, STS, etc.
- [ ] Confirm **DNS resolution** (`enableDnsSupport` and `enableDnsHostnames`) is enabled for VPC.  

### VPC Endpoints
- [ ] Ensure interface endpoints exist for:
  - S3, ECR (API + DKR), CloudWatch Logs, STS, EC2, KMS, SSM, Secrets Manager.
- [ ] Private DNS enabled for each endpoint.  
- [ ] Endpoint security groups restricted to EKS subnets only.  
- [ ] Endpoint policies limit access to required resources only.

### NACLs
- [ ] Inbound/outbound rules are **not allow-all** (`0.0.0.0/0 all traffic`).  
- [ ] Only internal VPC CIDRs and endpoint ENIs allowed.  
- [ ] Default-deny rule is present at the end of each direction.

### Security Groups
- [ ] No inbound or outbound `All traffic → 0.0.0.0/0`.  
- [ ] Restrict inbound ports to required services:
  - TCP 443 (control plane)
  - TCP 10250 (kubelet)
  - NodePort range 30000–32767 (if used)
- [ ] Use **SG references** between cluster, node, and load balancer SGs instead of public access.  
- [ ] Outbound limited to internal CIDRs or VPC endpoints.

---

## 🔒 2. Control Plane Access

- [ ] **Public access disabled** (private endpoint only) or tightly scoped with small `/32` CIDRs.  
- [ ] **Control plane logging** enabled for all categories:
  - `api`, `audit`, `authenticator`, `controllerManager`, `scheduler`.  
- [ ] Logs delivered to CloudWatch with ≥ 1 year retention.  
- [ ] GuardDuty / Security Hub enabled to monitor control-plane activity.  
- [ ] API server throttling and WAF protections applied if publicly accessible.  

---

## 🧠 3. Identity & Access Management (IAM)

### IAM Roles & Policies
- [ ] No `AdministratorAccess` or wildcard (`*:*`) policies attached to nodes or service accounts.  
- [ ] EKS cluster role includes only `AmazonEKSClusterPolicy` and `AmazonEKSServicePolicy`.  
- [ ] NodeInstanceRole scoped to node lifecycle and logging only.

### IRSA (IAM Roles for Service Accounts)
- [ ] OIDC provider associated with cluster.  
- [ ] Each service account that calls AWS APIs uses IRSA with a scoped trust policy.  
- [ ] Node roles do **not** hold AWS permissions required by pods.

### aws-auth ConfigMap
- [ ] Only necessary IAM roles/groups mapped.  
- [ ] Human IAM users not directly mapped—use role-based access or SSO integration.

---

## ⚙️ 4. RBAC & Kubernetes Access Controls

### ClusterRoleBindings
- [ ] Count and review all ClusterRoleBindings:
  - [ ] `cluster-admin` limited to a small, controlled group.
  - [ ] No bindings to `system:authenticated` or `system:unauthenticated`.
- [ ] Replace ClusterRoleBindings with namespace-scoped RoleBindings where possible.
- [ ] Use tools (e.g., **rback**, **kubescape**) for continuous RBAC audit.

### Admission Controls
- [ ] Enable **PodSecurity** (baseline or restricted profiles).  
- [ ] Use **OPA Gatekeeper** or **Kyverno** to enforce security policies.  
- [ ] Deny creation of privileged pods, hostPath mounts, and unsafe syscalls.

---

## 🧬 5. Workload & Runtime Security

- [ ] All workloads use non-root containers (`runAsNonRoot: true`).  
- [ ] `readOnlyRootFilesystem: true` enforced where possible.  
- [ ] Drop all unnecessary Linux capabilities.  
- [ ] Resource limits (`cpu`/`memory`) defined for every pod.  
- [ ] ImagePullPolicy set to `IfNotPresent` or `Always` with approved registries.  
- [ ] Admission control prevents unverified image registries.  
- [ ] Implement **NetworkPolicies** (default deny + explicit allow).  
- [ ] Apply namespace isolation—no shared service accounts across namespaces.  
- [ ] Disable access to the EC2 metadata service from pods unless required.  

---

## 🔐 6. Data Protection & Encryption

- [ ] **EKS Secrets** encrypted with a dedicated KMS CMK (`encryptionConfig`).  
- [ ] **EBS volumes** encrypted by default.  
- [ ] **EFS** or persistent volumes encrypted at rest and in transit.  
- [ ] **KMS key policies** restrict cross-account or broad principal access.  
- [ ] **Secrets Manager / Parameter Store** used for sensitive data; not raw Kubernetes secrets.  

---

## 📊 7. Observability & Threat Detection

- [ ] **CloudWatch / CloudTrail** logs enabled across all regions.  
- [ ] **VPC Flow Logs** enabled for all subnets.  
- [ ] **GuardDuty** and **Inspector** active for runtime and container findings.  
- [ ] **AWS Config** rules enabled:
  - `eks-cluster-no-public-access`
  - `vpc-sg-open-only-to-authorized-ports`
  - `vpc-security-group-egress-check`
  - `iam-role-least-privilege`
- [ ] Alerts integrated with SNS / Slack / Security Hub.

---

## 🧰 8. Image & Supply-Chain Security

- [ ] Container images scanned via **ECR Enhanced Scanning** or third-party tools.  
- [ ] Base images pinned by digest, not tag.  
- [ ] Signed images verified using **cosign** or equivalent.  
- [ ] Maintain a **private image mirror** for isolated environments.  
- [ ] Automate image refresh and patch pipeline.

---

## 🧾 9. Compliance & Governance

- [ ] **CIS EKS Benchmark** (`kube-bench`) run regularly.  
- [ ] **AWS Config Conformance Packs** for EKS and CIS Foundations applied.  
- [ ] **Centralized logging** (CloudWatch → S3 → Athena / SIEM).  
- [ ] Retention policy: logs ≥ 1 year, CloudTrail ≥ 7 years for compliance.  
- [ ] Document all security exceptions and change approvals.  

---

## 🧮 10. Continuous Monitoring & Automation

- [ ] Automated nightly job exports:
  - ClusterRoleBindings summary
  - SecurityGroup and NACL diffs
  - Config / GuardDuty findings
- [ ] CI/CD integrates static analysis for manifests (OPA, Polaris, KubeLinter).  
- [ ] Security dashboards for compliance KPIs (Config, Security Hub, Grafana).  
- [ ] Regular disaster-recovery test for etcd backups and node auto-scaling.

---

## ✅ Audit Summary Table (Template)

| Category | Control | Status | Notes |
|-----------|----------|---------|-------|
| Network | Private subnets, endpoints only | ☐ |  |
| Control Plane | Private API, logs enabled | ☐ |  |
| IAM | IRSA enforced, no wildcards | ☐ |  |
| RBAC | Minimal cluster-admins | ☐ |  |
| Workloads | PSS / NetworkPolicies | ☐ |  |
| Data Protection | KMS encryption applied | ☐ |  |
| Logging & Detection | GuardDuty + Config enabled | ☐ |  |
| Compliance | CIS benchmark passed | ☐ |  |

---

### 🧠 Recommended Audit Frequency
| Environment | Frequency |
|--------------|------------|
| Production | Monthly + after every major upgrade |
| Staging / Test | Quarterly |
| Dev / Sandbox | Bi-annual or as needed |

---

**Outcome:**  
A secure, least-privileged, observable, and compliant EKS environment aligned with AWS Best Practices, CIS EKS Benchmark, and common regulatory frameworks.