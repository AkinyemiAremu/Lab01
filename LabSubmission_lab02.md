## ILLINOIS TECH | College of Computing

## Q1. State is a secret.

- The admin password that was generated

- The internal token

- The internal certificate authority's private keys

Terraform must save them because it tracks every resource it oversees to plan modifications and identify drift. The state bucket is TLS-only, versioned to allow for the recovery of previous states, private (all public access is forbidden), and encrypted with AES256. In order to prevent two applications from simultaneously modifying the state and corrupting it, Terraform uses use_lockfile to construct a lock object in S3 while a run is underway.

## Q2. What makes a subnet private?

A subnet's route table, not its name, determines whether it is public or private. The public route table, which contains aws_route "public_internet" (network.tf lines 39–42), is used by public_a. The route sends all traffic (0.0.0.0/0) to the internet gateway. The only default route in private_a used for the private route is garbled; the table is private_via_nat (lines 51–54), which points to the network interface of the NAT instance. Line 60 selects the association with each.value.public? public: private.

If the private services also had public IPs, they would be directly accessible from the internet if an internet gateway route was added to the private route table. They wouldn't in this lab as the security groups are still in effect and map_public_ip_on_launch = false (line 29). A layer of protection would still be removed by the route.

Since IAM lacks a VPC endpoint, the lab utilizes a NAT instance so that the private servers can connect to it over HTTPS. A NAT instance is free-tier eligible, but you have to patch and manage it yourself. A managed NAT gateway costs approximately \$32 per month. It just forwards HTTPS. IAM doesn't provide interface endpoints, which are more private (traffic never leaves AWS) but cost money each hour.

## Q3. Two firewalls.

Rule 105 prohibits everyone else from using 8443, whereas Rule 100 permits your address on 8443. Rule 120 permits ports 1024-65535, including 8443; thus, the deny is required. Anyone on the internet could match rule 120 and gain entry without rule 105. Your address matches rule 100 first since rules are examined from the lowest number up, and the deny only affects the remaining addresses.

Replies are new traffic and require their own rules (the ephemeral ports in rule 120) as the network ACL is stateless. Because the security group is stateful, it automatically permits responses to connections that it has previously permitted.

Because security groups only permit, the ACL can do something the security group cannot: deny a particular address or port. The security group operates per instance rather than per subnet and can accomplish things that the ACL cannot: authorize by another security group (for instance, only the web server's group can contact a service).

## Q4. One server, one role.

The explosion radius is reduced by assigning a server and role to each microservice. The attacker only gains access to the permissions of the compromised service. When many services share a single role, a breach of any one of them exposes all of the role's capabilities, including activities that the other services require but this one does not (least privilege).

The sentence AttachOnlyTheMFAGuardPolicy in svc-onboarding.json.tftpl permits iam: AttachUserPolicy


## ILLINOIS TECH | College of Computing

only if ArnEquals on iam: PolicyARN, which must equal .../policy/nimbus/Nimbus-RequireMFA. This prevents the service from adding any policy, including AdministratorAccess.

If the policy were negligent, a service that could generate users may still escalate. For instance, if it allowed me to: It might create a user, attach AdministratorAccess to it, and log in as that user using AttachUserPolicy or iam: PutUserPolicy without the condition or on Resource: ".". Other paths are as follows:

CreateLoginProfile on an already-existing admin account, or CreateAccessKey on a privileged user. All of these are restricted to user/nimbus/* under this policy.

## Q5. Layers between services.

Layer: Network rules (ACL + security group.

Stops: Port scans and connections from other addresses or subnets to the private services.

Does not stop: An attacker already inside the allowed web server, who is on an allowed path.

Layer: Mutual TLS

Stops: A caller without a certificate signed by the lab CA. It also stops eavesdropping on the

traffic.

Does not stop: Someone who steals a valid service certificate and its private key.

Layer: Internal token.

Stops: A caller that has a valid certificate but doesn't know the shared token.

Does not stop: A leaked token. Anyone who has it can use it until it is rotated.

Layer: Admin JWT

Stops: A caller who is not a signed-in admin, even if they have the certificate and the token. Does not stop: A stolen JWT used before it expires (30 minutes.

## Q6. (explore). Where should secrets live?

- SSM Parameter Store SecureString: free, CloudTrail-logged, IAM-controlled, encrypted with an AWS- managed key. The lab utilizes rotate_token.sh because it lacks built-in rotation.

- Secrets Manager: around \$0.40 per secret per month, including CloudTrail audits, IAM and resource policies, and built-in rotation (for RDS, for example).

- HashiCorp Vault: it has rotation, fine-grained policies, dynamic, short-lived secrets, and comprehensive audit logs, but it is the most expensive to administer and secure.

Terraform keeps all resource attributes in the state file, secrets generated by Terraform (random_password, TLS keys) remain in clear text. There are two approaches to prevent that: either use write-only/ephemeral values or generate the secret outside of Terraform (for instance, in Secrets Manager with rotation) and only reference it.

## Q7. Anatomy of a JWT.

Three components make up a JWT: the payload (which contains the claims username = admin, cognito:groups = admins, iss, client_id, token_use = access, exp), the header (which contains the key id kid and the algorithm RS256), and the signature. They are all unencrypted; the payload and header are just Base64-encoded, so anyone with the token can read them. The signature just demonstrates that no one altered them. The token was rejected with an InvalidSignatureError in H3 after I changed the payload to say "mallory," and the previous signature no longer matched.


## ILLINOIS TECH | College of Computing

- the algorithm is on a fixed list (RS256);

- the signature matches Cognito's public keys;

- the issuer is our user pool;

- exp, iat, iss, and sub are present, and the token has not expired;

- token_use is access;

- client_id is our app client;

- the user is in the admins group.

Two of these prevent specific attacks. The fixed algorithm list stops an attacker from sending a token with alg: none (no signature) or switching to HS256 and signing it with the public key as a secret. The token_use and client_id checks stop an ID token, or a token issued for a different app or user pool, from being accepted as an admin access token.

## Q8. (explore). The limits of a bearer token.

JWTs are bearer tokens; they remain valid even after the administrator has departed until they expire. A stolen or stale token continues to function because each service only verifies the signature and expiration date, not a list of revoked users. Refresh tokens are not enabled here, and the 30-minute lifetime limits how long it may be abused. Because the console uses USER_PASSWORD_AUTH, the password is sent directly to the web application and could be intercepted by a compromised server. I would use the Cognito hosted user interface and the OAuth 2.0 authorization code flow with PKCE in production. The app only gets a temporary code; tokens can be revoked at the /oauth2/revoke endpoint, the password and MFA remain with Cognito, and single sign-on with an organization identity provider is supported.

## Q9. Plan, drift and immutable servers.

Terraform apply created 169 resources (terraform state list | wc -l). + denotes creation, ~ denotes change in place, -/+ denotes destruction and recreation (replace), and - denotes destruction in a plan. The object name and the servers' boot script change when one line of application code is changed because it modifies the zip's hash. Terraform replaces the servers with new ones (immutable infrastructure) rather than fixing them because a running server's boot script cannot be altered. Terraform Plan updated the actual state from AWS and compared it with the configuration and state file. It intended to return it to my /32 address after noticing that the rule's address (0.0.0.0/0) was different from the code. Because Terraform only tracks resources in its configuration and state, and an additional rule that isn't in the code is a resource it doesn't know about, a rule added by hand wouldn't appear in this plan.

## Q10. (explore). Prove it, then reflect.

The dashboard service requires an additional credential:

- No client certificate → 000: There was no HTTP response at all since the mutual TLS layer rejected the handshake.

- Certificate, no token → 401: The call was rejected by the service's internal token check after mutual TLS was successful.

- Certificate and token, no JWT → 401: The admin JWT check rejected it despite the first two tiers passing.

Nothing else the web server could do. The metadata request without a token returned 401, and both iam list-users and s3 ls returned AccessDenied (no IAM permission for the role, and the S3 call was denied by the VPC endpoint policy).

The dashboard service with one more credential each time:

- No client certificate  000: the mutual TLS layer refused the handshake, so no HTTP reply existed at


## ILLINOIS TECH | College of Computing

- all.

- Certificate, no token  401: mutual TLS passed, and the service's internal token check refused the call.

- Certificate and token, no JWT  401: the first two layers passed, and the admin JWT check refused it.

The web server's role could do nothing else. iam list-users and s3 ls both returned AccessDenied (no IAM permission for the role, and the S3 call was blocked by the VPC endpoint policy), and the metadata request without a token returned 401.

The instance's role credentials are shielded from a stolen request by IMDSv2 with a hop limit of 1. They cannot be obtained by a process running on the instance or by a bug like SSRF because the additional network hop is dropped and a session token is required. With no open port 22 and no shared key, Session Manager keeps track of who opened a shell, when, and, if enabled, each command and its output in CloudTrail and logs. SSH merely leaves the server with a login line.
