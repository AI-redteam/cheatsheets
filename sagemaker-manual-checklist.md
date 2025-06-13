# **SageMaker Manual Penetration Testing Checklist**

This checklist is designed for penetration testers to manually assess the security posture of an AWS SageMaker environment from within a notebook instance. All commands are intended to be run from a terminal inside SageMaker, using the credentials of the notebook's IAM execution role.

## **1\. Initial Enumeration & Role Analysis**

**Goal:** Understand the current IAM context and permissions.

* **\[ \] Get Current Identity:** Determine the ARN of the role you are operating as.  
  aws sts get-caller-identity \--query "Arn" \--output text

* **\[ \] List Attached Policies:** List all managed and inline policies attached to your current role. Note any policies that seem overly permissive by name (e.g., ending in FullAccess, Administrator).  
  \# Replace \<role-name\> with the role name from the ARN above  
  aws iam list-attached-role-policies \--role-name \<role-name\>  
  aws iam list-role-policies \--role-name \<role-name\>

* **\[ \] Get Default Policy Version:** Find the default version ID of a specific managed policy to analyze its contents.  
  \# Replace \<policy-arn\> with an ARN from the previous step  
  aws iam get-policy \--policy-arn \<policy-arn\> \--query "Policy.DefaultVersionId" \--output text

* **\[ \] Analyze Policy Contents:** Retrieve the JSON document of the policy to manually inspect its permissions.  
  \# Replace \<policy-arn\> and \<version-id\>  
  aws iam get-policy-version \--policy-arn \<policy-arn\> \--version-id \<version-id\>

## **2\. IAM Privilege Escalation Vectors**

**Goal:** Identify permissions that allow for direct privilege escalation within the AWS account.

* **\[ \] Check for User Creation Permissions:**  
  * **Permissions:** iam:CreateUser, iam:CreateAccessKey, iam:AttachUserPolicy  
  * **Test:** Can you create a new IAM user and grant it admin rights?  
  * **Exploit:** See aws-sagemaker-privesc.md for the full exploit chain.  
* **\[ \] Check for iam:PassRole Abuse:**  
  * **Permission:** iam:PassRole  
  * **Test:** Look for this permission in the analyzed policy documents. Pay special attention if Resource is "\*" or a list containing highly privileged roles.  
  * **Exploit:** If you also have ec2:RunInstances, you can launch a new EC2 instance and attach a privileged role to it.  
* **\[ \] Check for Policy Modification Permissions:**  
  * **Permission:** iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion  
  * **Test:** Can you create a new, more permissive version of an existing policy?  
  * **Exploit:** Add {"Action": "\*", "Resource": "\*", "Effect": "Allow"} to an existing policy that your user is attached to.  
* **\[ \] Check for Broad Wildcard Permissions:**  
  * **Permissions:** iam:\*, \*  
  * **Test:** Look for wildcards in the Action field of any policy statement. This is a clear indicator of a misconfiguration.

## **3\. Lifecycle Configuration (LCC) Attack Vectors**

**Goal:** Determine if you have the permissions to create and attach a malicious LCC for persistence or escalation.

* **\[ \] Check for LCC Creation Permissions:**  
  * **Permissions:** sagemaker:CreateNotebookInstanceLifecycleConfig, sagemaker:CreateStudioLifecycleConfig  
  * **Test:** Attempt to create a benign LCC.  
    \# Base64 encode a simple script  
    content=$(echo '\#\!/bin/bash \\n echo "test"' | base64 \-w 0\)

    \# Attempt to create the LCC  
    aws sagemaker create-notebook-instance-lifecycle-config \\  
      \--notebook-instance-lifecycle-config-name "pentest-check" \\  
      \--on-start Content=$content

* **\[ \] Check for LCC Attachment Permissions (Notebooks):**  
  * **Permission:** sagemaker:UpdateNotebookInstance, sagemaker:CreateNotebookInstance  
  * **Test:** Can you attach your test LCC to an existing (or new) notebook instance?  
* **\[ \] Check for LCC Attachment Permissions (Studio \- High Impact):**  
  * **Permissions:** sagemaker:UpdateDomain, sagemaker:UpdateUserProfile  
  * **Test:** Can you update a Studio domain or user profile to include your test LCC? This is a high-impact finding as it affects multiple users.

## **4\. Environment & Instance Misconfigurations**

**Goal:** Find weaknesses in the configuration of the SageMaker resources themselves.

* **\[ \] Check for Root Access on Notebooks:**  
  * **Test:** List all notebook instances and describe them to check the RootAccess field.  
    \# Get a list of instance names  
    aws sagemaker list-notebook-instances \--query "NotebookInstances\[\].NotebookInstanceName" \--output text

    \# Describe a specific instance  
    aws sagemaker describe-notebook-instance \--notebook-instance-name \<instance-name\>

  * **Finding:** If RootAccess is "Enabled", it's a finding.  
* **\[ \] Check IMDS Version:**  
  * **Test:** From the notebook terminal, attempt to access IMDSv1. If it succeeds, v1 is enabled.  
    \# If this returns a role name, IMDSv1 is active.  
    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

  * **Finding:** IMDSv1 is less secure than IMDSv2 and can be vulnerable to certain SSRF attacks.

## **5\. Data Exfiltration & Discovery Vectors**

**Goal:** Assess the potential blast radius for data theft and further discovery.

* **\[ \] Check for Broad S3 Access:**  
  * **Permissions:** s3:ListAllMyBuckets, s3:\*  
  * **Test:** Can you list all S3 buckets in the account? Can you read/write data from buckets not directly related to your project?  
    aws s3 ls  
    \# Attempt to access a sensitive-looking bucket  
    aws s3 ls s3://\<bucket-name\>/

* **\[ \] Check for Cross-Service Permissions:**  
  * **Test:** Review your IAM policies for permissions related to other services like ec2, rds, lambda, etc.  
  * **Finding:** Any non-SageMaker, non-S3 permissions should be noted, as they represent potential pivot points. For example, ec2:RunInstances combined with iam:PassRole is a critical finding.
