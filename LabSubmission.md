## ILLINOIS TECH | College of Computing

## Q1. (explore). Tests as security controls.

To prevent a failed test from blocking the merge before anything hits production, I would run the tests in the CI pipeline as a mandatory check on each pull request. They can't detect risks for which no test was written or drift in the live account, like a policy manually changed in the console. While the secret scanner in create_repo.sh detects compromised credentials that the policy tests do not search for, IAM Access Analyzer validation and cfn-guard or Open Policy Agent examine general policy rules without a special test.

## Q2. Why does Nimbus-Require MFA use BoolIfExists rather than Bool?

When an access key is used to sign a request, the key AWS: The request context lacks MultiFactorAuthPresent, and as a simple Bool would not match, the Deny would not be applicable. Since a missing key is treated as a match by BoolIfExists, the guard in the statement Deny Everything Except MFA Setup Access keys without an MFA session are also blocked by WhenNoMFA.

```
"Effect": "Deny",
"NotAction": [
"iam: ChangePassword",
"iam: GetUser",
"iam: CreateVirtualMFADevice",
iam :DeleteVirtualMFADevice",
"iam: EnableMFADevice",
"iam: ListMFADevices",
"iam: ListVirtualMFADevices",
lam: ResyncMFADevice",
"iam: GetAccountPasswordPolicy"
"sts
```

## Q3. In TechTeam-DevScoped, why is a Deny still useful when no Allow grants IAM access?

An explicit Deny overrides every Allow, so it still holds if another group, an inline policy or a future edit later grants those IAM actions. It is a guarantee that does not depend on what other policies contain.

## Q4. (explore). Group membership as an escalation path.


## ILLINOIS TECH | College of Computing

The group to join is Security Team because it lets me manage all of the lab's policies, including the Tech Team policy and the MFA guard, which are located under the Create Policy Version path on policy/nimbus*. Any member could rewrite these to remove the guard or allow widespread access. I would remove IAM and select a condition that restricts the group names that may be issued, supported by a permissions barrier (an SCP requires AWS Organizations, which the lab doesn't use): From Security Team, create Policy Version.

## 5. Name three places the admin password could have ended up if you had not used Secrets Manager. Why is each one worse?

- 1. The Git repository contains the source code: It was possible to commit the password after hardcoding it in a file. This made it worse because the repository is public (anyone can view it), and Git history is permanent, so removing the line later does not remove it from earlier commits.

- 2. An environment variable or container image: The compose file or the Docker file may have included the password. The situation is worse because images are copied to build caches and registries, and anyone who can retrieve the image or examine the container can read the password. Only the roles authorized to read it receive it from Secrets Manager.

Application logs: The password could have been printed by a log line or an error message. It is worse because logs are retained in CloudWatch for days, are readable by many people and tools, and are often copied into other systems. In this lab, log event masks fields named password, token, secret, or key as a second line of defense.

## 6. What does the TLS only bucket policy stop that Block Public Access does not?

It prevents eavesdropping and downgrade attacks on data in transit, even for authorized users, by rejecting any request sent over plain HTTP or an outdated TLS version. Block Public Access doesn't explain how authorized requests are encrypted on the wire; it only keeps the bucket from being public.

## 7. (explore). Customer-managed keys.

You may audit each decrypt in CloudTrail, isolate key administrators from key users, and disable the key to render data inaccessible with a customer-managed KMS key, all of which are not available with the default SSE-S3. With SSE-S3, anyone with s3:GetObject can access the data, but with a customer-managed key they also need kms: Decrypt. A key policy would limit the four service roles to kms: Decrypt and kms: GenerateDataKey only, with a kms: ViaService condition, and grant one admin role the management activities (create, disable, schedule deletion) and no decrypt. A mistake in the key policy or deleting the key will permanently lock everyone out of the data. The monthly costs are approximately \$1 per key + per-request fees (see current pricing).


## ILLINOIS TECH | College of Computing

- 8. For each of the three simulator results, name the Principal, Action, Resource and Request context, and say which statement decided it.

- 1. Action: IAM: AttachUserPolicy, Resource user/nimbus/alice, context iam:PolicyARN = AdministratorAccess → implicitDeny. The statement AttachOnlyTheMFAGuardPolicy allows this action only when the policy ARN equals Nimbus-RequireMFA, so its condition fails, no Allow matches, and the default deny applies.

- 2. Action iam:AttachUserPolicy, Resource user/nimbus/alice, context iam:PolicyARN = Nimbus-RequireMFA → allowed. AttachOnlyTheMFAGuardPolicy matches because the resource is under /nimbus/ and the condition is met.

- 3. Action iam:CreateLoginProfile, Resource user/Aremu_Akinyemi, no special context → implicitDeny. CreateAndTagNimbusUsersOnly allows this action only on user/nimbus/*, and the lab user lives outside that path, so no statement matches.

SimulatePrincipalPolicy

|

iam:CreatelLoginProfile

implicitDeny

## 9. (explore). Four containers, one host.

A compromised container can retrieve the instance credentials and assume any of the four service roles (e.g., the web container becoming nimbus-onboarding-svc) because the hop limit of two allows a container to reach the instance metadata service via the Docker bridge. The strongest isolation is provided by one instance per service, but this exceeds the free tier and costs four times the compute. At a moderate setup effort, ECS task roles assign each job its own role and prevent containers from reaching the instance role; Fargate increases the cost. The EKS


## ILLINOIS TECH | College of Computing

control plane requires the most operational effort and costs about \$0.10 per hour, but Kubernetes pod-level identification (EKS Pod identification or IRSA) isolates best per workload.

## Q10. Which two kinds of event does the lab alert on, and why alert on them instead of only storing them?

It warns about risky IAM modifications, such as creating access keys, writing policies or trust policies, and attaching AdministratorAccess, as well as console sign-ins without MFA. While an alert reaches a human within minutes, there is still time to contain the attack; stored logs are only read when someone decides to look.

## Q11. (explore). Blind spots in detection.

The rules would miss an attacker who creates or resets a console password for an existing user (CreateLoginProfile or UpdateLoginProfile), and one who uses stolen credentials from an unusual location, because neither rule looks at those events or at the source IP. A pattern for the first one:

```
json
{
"source": ["aws.iam"],
"detail-type": ["AWS API Call via CloudTrail"],
"detail": {
"eventSource": ["iam.amazonaws.com"],
"eventName": ["CreateLoginProfile", "UpdateLoginProfile"]
}
}
```

The onboarding service provided by CreateLoginProfile for each new hire; therefore, unless that role is excluded, this pattern would fire on all valid onboardings. When people receive too


## ILLINOIS TECH | College of Computing

many of these notifications, they become alert fatigued and disregard the important ones. Amazon GuardDuty takes a different approach: without requiring you to write a rule for every instance, it learns typical behavior from CloudTrail, flow logs, and DNS logs, combines it with threat intelligence, and provides severity-ranked results, such as credentials used from an unusual location.

## Q12. Why is there no SSH and no key pair, and how do you debug the server without them?

With no SSH and no key pair, there is no login path to attack, no key to steal or leak, and no port 22 to scan. You debug through the instance’s console output (get-console-output) and the container logs in the CloudWatch log group /lab01/app.

## Q13. If the web container were compromised, what does egress filtering stop and what does it not stop?

It stops the attacker from reaching any port except 443 and 80, so they can’t open an arbitrary reverse shell or use other protocols to exfiltrate data. It doesn’t stop traffic over 443 to any host, such as an attacker’s own server or bucket, because security groups can’t filter by hostname, and it doesn’t filter DNS or the metadata service.

## Q14. (explore). Certificates and trust on first use.

The fingerprint comparison defends against a man-in-the-middle attack: on the first visit, the browser cannot verify a self-signed certificate, so an attacker on the network path could present their own and read the admin password. Comparing the fingerprint with the one the server printed to its console proves the certificate is ours, because the attacker doesn’t control that channel. Most users skip it because the warning is routine, the comparison is tedious, and clicking through is easier. A certificate from AWS Certificate Manager is browser-trusted and renews itself, but it needs a load balancer, which the free-tier rules here forbid. A public certificate authority such as Let’s Encrypt is also trusted and free, but it needs a domain name. HSTS makes the browser insist on HTTPS after the first visit, which prevents downgrade, but it doesn’t protect that first visit with a self-signed certificate. Certificate transparency publishes every publicly trusted certificate in open logs so a mis-issued one can be detected, and it doesn’t cover self-signed ones at all.

## Q15. Which of the six checks proved encryption in transit, which proved a smaller attack surface, and which proved protection against password guessing?

Check 1 (HTTPS returns 200 while plain HTTP gets no usable reply) and the Strict-Transport- Security header in check 2 proved encryption in transit. Check 3 (ports 22 and 8080 closed) and check 5 (only 8443 inbound and only 80 and 443 outbound) proved the smaller attack surface, and Check 4 proved protection against password guessing: the 429 responses appeared after


## ILLINOIS TECH | College of Computing

about ten wrong passwords, because each of the server’s two workers keeps its own count of five failures.

Q16. Why does the same user and action get denied without MFA and allowed with it? Quote the condition key.

The Nimbus-Require MFA policy denies everything except MFA setup when the condition "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"} is true, so a request without MFA is denied. With MFA the key is true, so the Deny does not apply and the group’s Allow takes effect.

James ok


## ILLINOIS TECH | College of Computing

William Drift confirmation

## Q17. Who created Mallory, and how did you find out? Why does the audit trail in S3 not show it?

CloudTrail’s CreateUser event names the caller, user Aremu_Akinyemi, and the Dashboard flagged Mallory as UNTRACKED because IAM had her, but the registry had no record. The S3 audit trail shows nothing because only the onboarding service writes audit entries, and I created her directly with the CLI, bypassing the application.

Created by Aremu_akinyemi

## Q18. (explore). Replacing IAM users with single sign on.

IAM Identity Center and an external identity provider, IAM users, login profiles, one-time passwords, and the per-user MFA enrolment flow become unnecessary, along with the Onboarding service’s user creation. The MFA requirement (enforced at the provider), the kill switch (disable the account in the provider and remove assignments), drift detection (assignments against the HR roster), and the CloudTrail alerts all still matter. New risks are a compromised identity provider (every account falls at once), delays when changes sync to AWS, and a break-glass admin that bypasses SSO.

## Q19. Why is a token rotation safe with no restart, and what would break if the services accepted only the current token?

Each service accepts both the current and the previous token version, and refreshes its cache once when a token is rejected, so a service still holding the old token keeps working until its cache refreshes. If only the current token were accepted, every request from a service with a stale cached token would get a 401 for up to the 60-second cache window, which would be an outage.

Q20. Which control would have prevented the incident, and which only limited it? Name one more free control you would add.

The controls limited the incident rather than preventing it, because the stolen lab user has broad IAM rights and could create the key: TechTeam’s Deny statements capped what james’s key could do, CloudTrail recorded who created it, and Nimbus-DenyAll neutralised it in one call. The alert email that should have flagged the new key never arrived, which is a detection gap, and


## ILLINOIS TECH | College of Computing

one free control I would add is requiring MFA for the lab user’s IAM write actions, using the BoolIfExists pattern from Nimbus-RequireMFA.

## Q21. (explore). Mapping the drill to a framework.

The stolen lab user maps to Valid Accounts: Cloud Accounts (T1078.004) and the backdoor key to Account Manipulation: Additional Cloud Credentials (T1098.001), with offboarding mitigating through privileged account management and MFA. Three lab controls map to the CIS AWS Foundations Benchmark: the MFA guard to MFA for console users, the trail with log file validation to CloudTrail enablement and integrity, and Block Public Access to non-public log buckets. One requirement the lab does not meet is CloudTrail in all regions, because its trail is single-region.

Q22. Complete the table in your own words: which limit do you hit first in each row, and what do you change?

| Concern First limit | What I would change |
| --- | --- |
|   | Use IAM Identity Center so people |
| Permissions The 5,000-user IAM quota |   |
|   | are not IAM users |
|   | Move records to DynamoDB, or |
| Registry Listing 10,000+ objects on every refresh |   |
|   | cache and index the listing |
| IAM API throttling from about 5 calls per | Use the IAM credential report and |
| Dashboard |   |
| user (above ~1,000 users) | cache longer |
| Service All four containers share one host, so one | ECS task roles or one instance per |
| identity compromise can assume any role | service |
| One shared password and a per-worker | Single sign-on with MFA at the |
| Sign in |   |
| lockout | identity provider |
| More CloudTrail volume on a single-region | A multi-region trail to a central log |
| Logging |   |
| trail | account with a SIEM |

Q23. (explore). Controls that even an administrator cannot remove.

An SCP attached to the organization can deny the actions that would remove each control, except for a break-glass role:

```
json
{
"Version": "2012-10-17",
"Statement": [
{"Sid": "ProtectTrail", "Effect": "Deny",
"Action":
["cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail","cloudtrail:PutEvent Selectors"],
"Resource": "arn:aws:cloudtrail:*:*:trail/lab01-trail",
```


## ILLINOIS TECH | College of Computing

```
"Condition": {"ArnNotLike": {"aws:PrincipalArn":
"arn:aws:iam::*:role/BreakGlassAdmin"}}},
{"Sid": "ProtectDenyAllPolicy", "Effect": "Deny",
"Action":
["iam:DeletePolicy","iam:DeletePolicyVersion","iam:CreatePolicyVersion","iam:SetDefaultPoli
cyVersion"],
"Resource": "arn:aws:iam::*:policy/nimbus/Nimbus-DenyAll",
"Condition": {"ArnNotLike": {"aws:PrincipalArn":
"arn:aws:iam::*:role/BreakGlassAdmin"}}},
{"Sid": "ProtectBlockPublicAccess", "Effect": "Deny",
"Action": ["s3:PutAccountPublicAccessBlock","s3:PutBucketPublicAccessBlock"],
"Resource": "*",
"Condition": {"ArnNotLike": {"aws:PrincipalArn":
"arn:aws:iam::*:role/BreakGlassAdmin"}}}
]
}
```

Also deny the three Detach*Policy actions when iam: PolicyARN equals the Deny-all poslicy. An SCP never grants permission, and it doesn’t restrict the management account, service-linked roles, or people outside the organization using resource policies. The management account is exempt because it creates and attaches SCPs; applying them to it could lock the whole organization out, so workloads must stay out of it.

```
Q24. (explore). Can you trust the logs?
```

The log file validation on CloudTrail writes an hourly digest file containing hashes of that hour’s logs, signed by AWS and linked to the previous digest, so a changed or missing log file shows up as a failure. aws cloudtrail validate-logs recomputes the hashes and checks the signatures. An administrator in this lab could stop or delete the trail and delete the logs and digests together from the same bucket, which is what the cleanup script does. A separate log archive account with a write-only bucket policy, S3 Object Lock in compliance mode, and MFA delete would stop that, because the logs could not be deleted or overwritten during the retention period. References: CloudTrail User Guide, “Validating log file integrity,” and S3 User Guide, “Using S3 Object Lock.

Clean up evidence
