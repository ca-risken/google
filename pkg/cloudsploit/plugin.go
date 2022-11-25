package cloudsploit

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

type pluginMetaData struct {
	Score     float32
	Recommend recommend
	Tag       []string
}

// pluginMap maps cloudsploit plugin meta data.
// key: `{Categor}/{Plugin}`, value: tag
var pluginMap = map[string]pluginMetaData{
	categoryCLB + "/clbCDNEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `CLB CDN Enabled
			- Ensures that Cloud CDN is enabled on all load balancers
			- Cloud CDN increases speed and reliability as well as lowers server costs.
			- Enabling CDN on load balancers creates a highly available system and is part of GCP best practices.`,
			Recommendation: `Enable Cloud CDN on all load balancers from the network services console.
			- https://cloud.google.com/cdn/docs/quickstart`,
		},
	},
	categoryCLB + "/clbHttpsOnly": {
		Score: 0.3,
		Tag:   []string{"hippa", "pci"},
		Recommend: recommend{
			Risk: `CLB HTTPS Only
			- Ensures that HTTP(S) CLBs are configured to only accept connections on HTTPS ports.
			- For maximum security, CLBs can be configured to only accept HTTPS connections. Standard HTTP connections will be blocked.
			- This should only be done if the client application is configured to query HTTPS directly and not rely on a redirect from HTTP.`,
			Recommendation: `Remove non-HTTPS listeners from the load balancer.
			- https://cloud.google.com/vpc/docs/vpc`,
		},
	},
	categoryCLB + "/clbNoInstances": {
		Score: 0.3,
		Tag:   []string{"operation"},
		Recommend: recommend{
			Risk: `CLB No Instances
			- Detects CLBs that have no backend instances attached
			- GCP does not allow for Load Balancers to be configured without backend instances attached.`,
			Recommendation: `This security misconfiguration is covered by GCP. No action is necessary.
			- https://cloud.google.com/load-balancing/docs/load-balancing-overview`,
		},
	},
	categoryCLB + "/clbSecurityPolicyEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Security Policy Enabled
			- Ensures all backend services have an attached security policy
			- Security policies on backend services control the traffic on the load balancer.
			- This creates edge security and can deny or allow specified IP addresses.`,
			Recommendation: `Ensure all load balancers have an attached Cloud Armor security policy.
			- https://cloud.google.com/armor/docs/security-policy-concepts`,
		},
	},

	categoryCompute + "/autoscaleEnabled": {
		Score: 0.3,
		Tag:   []string{"reliability"},
		Recommend: recommend{
			Risk: `Autoscale Enabled
			- Ensures instance groups have autoscale enabled for high availability
			- Enabling autoscale increases efficiency and improves cost management for resources.`,
			Recommendation: `Ensure autoscaling is enabled for all instance groups.
			- https://cloud.google.com/compute/docs/autoscaler/`,
		},
	},
	categoryCompute + "/connectSerialPortsDisabled": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Connect Serial Ports Disabled
			- Ensures connecting to serial ports is not enabled for VM instances
			- The serial console does not allow restricting IP Addresses, which allows any IP address to connect to instance and should therefore be disabled.`,
			Recommendation: `Ensure the Enable Connecting to Serial Ports option is disabled for all compute instances.
			- https://cloud.google.com/compute/docs/instances/interacting-with-serial-console`,
		},
	},
	categoryCompute + "/csekEncryptionEnabled": {
		Score: 0.3,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `CSEK Encryption Enabled
			- Ensures Customer Supplied Encryption Key Encryption is enabled on disks
			- Google encrypts all disks at rest by default.
			- By using CSEK only the users with the key can access the disk.
			- Anyone else, including Google, cannot access the disk data.`,
			Recommendation: `CSEK can only be configured when creating a disk.
			- Delete the disk and redeploy with CSEK.
			- https://cloud.google.com/compute/docs/disks/customer-supplied-encryption`,
		},
	},
	categoryCompute + "/instanceLeastPrivilege": {
		Score: 0.6,
		Tag:   []string{"pci"},
		Recommend: recommend{
			Risk: `VM Instances Least Privilege
			- Ensures that instances are not configured to use the default service account with full access to all cloud APIs
			- To support the principle of least privilege and prevent potential privilege escalation, it is recommended that instances are not assigned to the default service account, Compute Engine default service account with a scope allowing full access to all cloud APIs.`,
			Recommendation: `For all instances, if the default service account is used, ensure full access to all cloud APIs is not configured.
			- https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances`,
		},
	},
	categoryCompute + "/instanceLevelSSHOnly": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Instance Level SSH Only
			- Ensures that instances are not configured to allow project-wide SSH keys
			- To support the principle of least privilege and prevent potential privilege escalation it is recommended that instances are not give access to project-wide SSH keys through instance metadata.`,
			Recommendation: `Ensure project-wide SSH keys are blocked for all instances.
			- https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys`,
		},
	},
	categoryCompute + "/instanceMaxCount": {
		Score: 0.3,
		Tag:   []string{"reliability"},
		Recommend: recommend{
			Risk: `VM Max Instances
			- Ensures the total number of VM instances does not exceed a set threshold
			- The number of running VM instances should be carefully audited, especially in unused regions, to ensure only approved applications are consuming compute resources.
			- Many compromised Google accounts see large numbers of VM instances launched.`,
			Recommendation: `Ensure that the number of running VM instances matches the expected count.
			- If instances are launched above the threshold, investigate to ensure they are legitimate.
			- https://cloud.google.com/compute/docs/instances/`,
		},
	},
	categoryCompute + "/instancesMultiAz": {
		Score: 0.3,
		Tag:   []string{"reliability"},
		Recommend: recommend{
			Risk: `Instances Multi AZ
			- Ensures managed instances are regional for availability purposes.
			- Creating instances in a single zone creates a single point of failure for all systems in the VPC.
			- All managed instances should be created as Regional to ensure proper failover.`,
			Recommendation: `Launch new instances as regional instance groups.
			- https://cloud.google.com/vpc/docs/vpc`,
		},
	},
	categoryCompute + "/ipForwardingDisabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `IP Forwarding Disabled
			- Ensures that IP forwarding is disabled on all instances
			- Disabling IP forwarding ensures that the instance only sends and receives packets with matching destination or source IPs.`,
			Recommendation: `IP forwarding settings can only be chosen when creating a new instance.
			- Delete the affected instances and redeploy with IP forwarding disabled.
			- https://cloud.google.com/vpc/docs/using-routes`,
		},
	},
	categoryCompute + "/osLoginEnabled": {
		Score: 0.3,
		Tag:   []string{"pci"},
		Recommend: recommend{
			Risk: `OS Login Enabled
			- Ensures OS login is enabled for the project
			- Enabling OS login ensures that SSH keys used to connect to instances are mapped with IAM users.`,
			Recommendation: `Set enable-oslogin in project-wide metadata so that it applies to all of the instances in the project.
			- https://cloud.google.com/compute/docs/instances/managing-instance-access`,
		},
	},

	categoryCryptographicKeys + "/keyRotation": {
		Score: 0.3,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `Key Rotation
			- Ensures cryptographic keys are set to rotate on a regular schedule
			- All cryptographic keys should have key rotation enabled.
			- Google will handle the rotation of the encryption key itself, as well as storage of previous keys, so previous data does not need to be re-encrypted before the rotation occurs.`,
			Recommendation: `Ensure that cryptographic keys are set to rotate.
			- https://cloud.google.com/vpc/docs/using-cryptoKeys`,
		},
	},

	categoryDNS + "/dnsSecEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `DNS Security Enabled
			- Ensures that DNS Security is enabled on all managed zones
			- DNS Security is a feature that authenticates all responses to domain name lookups.
			- This prevents attackers from committing DNS hijacking or man in the middle attacks.`,
			Recommendation: `Ensure DNSSEC is enabled for all managed zones in the cloud DNS service.
			- https://cloud.google.com/dns/docs/dnssec`,
		},
	},
	categoryDNS + "/dnsSecSigningAlgorithm": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `DNS Security Signing Algorithm
			- Ensures that DNS Security is not using the RSASHA1 algorithm for key or zone signing
			- DNS Security is a feature that authenticates all responses to domain name lookups.
			- This prevents attackers from committing DNS hijacking or man in the middle attacks.`,
			Recommendation: `Ensure that all managed zones using DNSSEC are not using the RSASHA1 algorithm for key or zone signing.
			- https://cloud.google.com/dns/docs/dnssec`,
		},
	},

	categoryIAM + "/corporateEmailsOnly": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Corporate Emails Only
			- Ensures that no users are using their Gmail accounts for access to GCP.
			- Gmail accounts are personally created and are not controlled by organizations.
			- Fully managed accounts are recommended for increased visibility, auditing and control over access to resources.`,
			Recommendation: `Ensure that no users are actively using their Gmail accounts to access GCP.
			- https://cloud.google.com/iam/docs/overview`,
		},
	},
	categoryIAM + "/kmsUserSeparation": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `KMS User Separation
			- Ensures that no users have the KMS admin role and any one of the CryptoKey roles.
			- Ensuring that no users have the KMS admin role and any one of the CryptoKey roles follows separation of duties, where no user should have access to resources out of the scope of duty.`,
			Recommendation: `Ensure that no service accounts have both the KMS admin role and any of CryptoKey roles attached.
			- https://cloud.google.com/iam/docs/overview`,
		},
	},
	categoryIAM + "/serviceAccountAdmin": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Service Account Admin
			- Ensures that user managed service accounts do not have any admin, owner, or write privileges.
			- Service accounts are primarily used for API access to Google. It is recommended to not use admin access for service accounts.`,
			Recommendation: `Ensure that no service accounts have admin, owner, or write privileges.
			- https://cloud.google.com/iam/docs/overview`,
		},
	},
	categoryIAM + "/serviceAccountKeyRotation": {
		Score: 0.3,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `Service Account Key Rotation
			- Ensures that service account keys are rotated within 90 days of creation.
			- Service account keys should be rotated so older keys that that might have been lost or compromised cannot be used to access Google services.`,
			Recommendation: `Rotate service account keys that have not been rotated in over 90 days.
			- https://cloud.google.com/iam/docs/creating-managing-service-account-keys`,
		},
	},
	categoryIAM + "/serviceAccountManagedKeys": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Service Account Managed Keys
			- Ensures that service account keys are being managed by Google.
			- Service account keys should be managed by Google to ensure that they are as secure as possible, including key rotations and restrictions to the accessibility of the keys.`,
			Recommendation: `Ensure all user service account keys are being managed by Google.
			- https://cloud.google.com/iam/docs/creating-managing-service-account-keys`,
		},
	},
	categoryIAM + "/serviceAccountSeparation": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Service Account Separation
			- Ensures that no users have both the Service Account User and Service Account Admin role.
			- Ensuring that no users have both roles follows separation of duties, where no user should have access to resources out of the scope of duty.`,
			Recommendation: `Ensure that no service accounts have both the Service Account User and Service Account Admin role attached.
			- https://cloud.google.com/iam/docs/overview`,
		},
	},
	categoryIAM + "/serviceAccountUser": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Service Account User
			- Ensures that no users have the Service Account User role.
			- The Service Account User role gives users the access to all service accounts of a project.
			- This can result in an elevation of privileges and is not recommended.`,
			Recommendation: `Ensure that no service accounts have the Service Account User role attached.
			- https://cloud.google.com/iam/docs/overview`,
		},
	},
	categoryIAM + "/serviceLimits": {
		Score: 0.3,
		Tag:   []string{"reliability"},
		Recommend: recommend{
			Risk: `Service Limits
			- Determines if the number of resources is close to the per-account limit.
			- Google limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.`,
			Recommendation: `Contact GCP support to increase the number of resources available
			- https://cloud.google.com/resource-manager/docs/limits`,
		},
	},

	categoryKubernetes + "/aliasIpRangesEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Alias IP Ranges Enabled
			- Ensures all Kubernetes clusters have alias IP ranges enabled
			- Alias IP ranges allow users to assign ranges of internal IP addresses as alias to a network interface.`,
			Recommendation: `Ensure that Kubernetes clusters have alias IP ranges enabled.
			- https://cloud.google.com/monitoring/kubernetes-engine/`,
		},
	},
	categoryKubernetes + "/autoNodeRepairEnabled": {
		Score: 0.3,
		Tag:   []string{"reliability"},
		Recommend: recommend{
			Risk: `Automatic Node Repair Enabled
			- Ensures all Kubernetes cluster nodes have automatic repair enabled
			- When automatic repair on nodes is enabled, the Kubernetes engine performs health checks on all nodes, automatically repairing nodes that fail health checks.
			- This ensures that the Kubernetes environment stays optimal.`,
			Recommendation: `Ensure that automatic node repair is enabled on all node pools in Kubernetes clusters
			- https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-repair`,
		},
	},
	categoryKubernetes + "/autoNodeUpgradesEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Automatic Node Upgrades Enabled
			- Ensures all Kubernetes cluster nodes have automatic upgrades enabled
			- Enabling automatic upgrades on nodes ensures that each node stays current with the latest version of the master branch, also ensuring that the latest security patches are installed to provide the most secure environment.`,
			Recommendation: `Ensure that automatic node upgrades are enabled on all node pools in Kubernetes clusters
			- https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-upgrades`,
		},
	},
	categoryKubernetes + "/basicAuthenticationDisabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Basic Authentication Disabled
			- Ensure basic authentication is set to disabled on Kubernetes clusters.
			- Basic authentication uses static passwords to authenticate, which is not the recommended method to authenticate into the Kubernetes API server.`,
			Recommendation: `Disable basic authentication on all clusters
			- https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster`,
		},
	},
	categoryKubernetes + "/clusterLabelsAdded": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Cluster Labels Added
			- Ensures all Kubernetes clusters have labels added
			- It is recommended to add labels to Kubernetes clusters to apply specific security settings and auto configure objects at creation.`,
			Recommendation: `Ensure labels are added to Kubernetes clusters
			- https://cloud.google.com/kubernetes-engine/docs/how-to/creating-managing-labels`,
		},
	},
	categoryKubernetes + "/clusterLeastPrivilege": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Cluster Least Privilege
			- Ensures Kubernetes clusters using default service account are using minimal service account access scopes
			- As a best practice, Kubernetes clusters should not be created with default service account.
			- But if they are, Kubernetes default service account should be limited to minimal access scopes necessary to operate the clusters.`,
			Recommendation: `Ensure that all Kubernetes clusters are created with minimal access scope.
			- https://cloud.google.com/compute/docs/access/service-accounts`,
		},
	},
	categoryKubernetes + "/cosImageEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `COS Image Enabled
			- Ensures all Kubernetes cluster nodes have Container-Optimized OS enabled
			- Container-Optimized OS is optimized to enhance node security.
			- It is backed by a team at Google that can quickly patch it.`,
			Recommendation: `Enable Container-Optimized OS on all Kubernetes cluster nodes
			- https://cloud.google.com/container-optimized-os/`,
		},
	},
	categoryKubernetes + "/defaultServiceAccount": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Default Service Account
			- Ensures all Kubernetes cluster nodes are not using the default service account.
			- Kubernetes cluster nodes should use customized service accounts that have minimal privileges to run.
			- This reduces the attack surface in the case of a malicious attack on the cluster.`,
			Recommendation: `Ensure that no Kubernetes cluster nodes are using the default service account
			- https://cloud.google.com/container-optimized-os/`,
		},
	},
	categoryKubernetes + "/legacyAuthorizationDisabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Legacy Authorization Disabled
			- Ensure legacy authorization is set to disabled on Kubernetes clusters
			- The legacy authorizer in Kubernetes grants broad, statically defined permissions.`,
			Recommendation: `Disable legacy authorization on all clusters.
			- https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster`,
		},
	},
	categoryKubernetes + "/loggingEnabled": {
		Score: 0.6,
		Tag:   []string{"hipaa"},
		Recommend: recommend{
			Risk: `Logging Enabled
			- Ensures all Kubernetes clusters have logging enabled
			- This setting should be enabled to ensure Kubernetes control plane logs are properly recorded.`,
			Recommendation: `Ensure that logging is enabled on all Kubernetes clusters.
			- https://cloud.google.com/monitoring/kubernetes-engine/legacy-stackdriver/logging`,
		},
	},
	categoryKubernetes + "/masterAuthorizedNetwork": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Master Authorized Network
			- Ensures master authorized networks is set to enabled on Kubernetes clusters
			- Authorized networks are a way of specifying a restricted range of IP addresses that are permitted to access your container clusters Kubernetes master endpoint.`,
			Recommendation: `Enable master authorized networks on all clusters.
			- https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks`,
		},
	},
	categoryKubernetes + "/monitoringEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Monitoring Enabled
			- Ensures all Kubernetes clusters have monitoring enabled
			- Kubernetes supports monitoring through Stackdriver.`,
			Recommendation: `Ensure monitoring is enabled on all Kubernetes clusters.
			- https://cloud.google.com/monitoring/kubernetes-engine/`,
		},
	},
	categoryKubernetes + "/networkPolicyEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Network Policy Enabled
			- Ensures all Kubernetes clusters have network policy enabled
			- Kubernetes network policy creates isolation between cluster pods, this creates a more secure environment with only specified connections allowed.`,
			Recommendation: `Enable network policy on all Kubernetes clusters.
			- https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy`,
		},
	},
	categoryKubernetes + "/podSecurityPolicyEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Pod Security Policy Enabled
			- Ensures pod security policy is enabled for all Kubernetes clusters
			- Kubernetes pod security policy is a resource that controls security sensitive aspects of the pod configuration.`,
			Recommendation: `Ensure that all Kubernetes clusters have pod security policy enabled.
			- https://cloud.google.com/kubernetes-engine/docs/how-to/pod-security-policies`,
		},
	},
	categoryKubernetes + "/privateClusterEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Private Cluster Enabled
			- Ensures private cluster is enabled for all Kubernetes clusters
			- Kubernetes private clusters only have internal ip ranges, which ensures that their workloads are isolated from the public internet.`,
			Recommendation: `Ensure that all Kubernetes clusters have private cluster enabled.
			- https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters`,
		},
	},
	categoryKubernetes + "/privateEndpoint": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Private Endpoint
			- Ensures the private endpoint setting is enabled for kubernetes clusters
			- kubernetes private endpoints can be used to route all traffic between the Kubernetes worker and control plane nodes over a private VPC endpoint rather than across the public internet.`,
			Recommendation: `Enable the private endpoint setting for all GKE clusters when creating the cluster.
			- https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters`,
		},
	},
	categoryKubernetes + "/webDashboardDisabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Web Dashboard Disabled
			- Ensures all Kubernetes clusters have the web dashboard disabled.
			- It is recommended to disable the web dashboard because it is backed by a highly privileged service account.`,
			Recommendation: `Ensure that no Kubernetes clusters have the web dashboard enabled
			- https://cloud.google.com/kubernetes-engine/docs/concepts/dashboards`,
		},
	},

	categoryLogging + "/auditConfigurationLogging": {
		Score: 0.3,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `Audit Configuration Logging
			- Ensures that logging and log alerts exist for audit configuration changes.
			- Project Ownership is the highest level of privilege on a project, any changes in audit configuration should be heavily monitored to prevent unauthorized changes.`,
			Recommendation: `Ensure that log alerts exist for audit configuration changes.
			- https://cloud.google.com/logging/docs/logs-based-metrics/`,
		},
	},
	categoryLogging + "/auditLoggingEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Audit Logging Enabled
			- Ensures that default audit logging is enabled on the organization or project.
			- The default audit logs should be configured to log all admin activities and write and read access to data for all services.
			- In addition, no exempted members should be added to the logs to ensure proper delivery of all audit logs.`,
			Recommendation: `Ensure that the default audit logs are enabled to log all admin activities and write and read access to data for all services.
			- https://cloud.google.com/logging/docs/audit/`,
		},
	},
	categoryLogging + "/customRoleLogging": {
		Score: 0.3,
		Tag:   []string{"hipaa"},
		Recommend: recommend{
			Risk: `Custom Role Logging
			- Ensures that logging and log alerts exist for custom role creation and changes
			- Project Ownership is the highest level of privilege on a project, any changes in custom role should be heavily monitored to prevent unauthorized changes.`,
			Recommendation: `Ensure that log alerts exist for custom role creation and changes.
			- https://cloud.google.com/logging/docs/logs-based-metrics/`,
		},
	},
	categoryLogging + "/logSinksEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Log Sinks Enabled
			- Ensures a log sink is enabled to export all logs
			- Log sinks send log data to a storage service for archival and compliance. A log sink with no filter is necessary to ensure that all logs are being properly sent.
			- If logs are sent to a storage bucket, the bucket must exist and bucket versioning should exist.`,
			Recommendation: `Ensure a log sink is configured properly with an empty filter and a destination.
			- https://cloud.google.com/logging/docs/export/`,
		},
	},
	categoryLogging + "/projectOwnershipLogging": {
		Score: 0.3,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `Project Ownership Logging
			- Ensures that logging and log alerts exist for project ownership assignments and changes
			- Project Ownership is the highest level of privilege on a project, any changes in project ownership should be heavily monitored to prevent unauthorized changes.`,
			Recommendation: `Ensure that log alerts exist for project ownership assignments and changes.
			- https://cloud.google.com/logging/docs/logs-based-metrics/`,
		},
	},
	categoryLogging + "/sqlConfigurationLogging": {
		Score: 0.3,
		Tag:   []string{"hipaa"},
		Recommend: recommend{
			Risk: `SQL Configuration Logging
			- Ensures that logging and log alerts exist for SQL configuration changes
			- Project Ownership is the highest level of privilege on a project, any changes in SQL configurations should be heavily monitored to prevent unauthorized changes.`,
			Recommendation: `Ensure that log alerts exist for SQL configuration changes.
			- https://cloud.google.com/logging/docs/logs-based-metrics/`,
		},
	},
	categoryLogging + "/storagePermissionsLogging": {
		Score: 0.3,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `Storage Permissions Logging
			- Ensures that logging and log alerts exist for storage permission changes
			- Storage permissions include access to the buckets that store the logs, any changes in storage permissions should be heavily monitored to prevent unauthorized changes.`,
			Recommendation: `Ensure that log alerts exist for storage permission changes.
			- https://cloud.google.com/logging/docs/logs-based-metrics/`,
		},
	},
	categoryLogging + "/vpcFirewallRuleLogging": {
		Score: 0.3,
		Tag:   []string{"hipaa"},
		Recommend: recommend{
			Risk: `VPC Firewall Rule Logging
			- Ensures that logging and log alerts exist for firewall rule changes
			- Project Ownership is the highest level of privilege on a project, any changes in firewall rule should be heavily monitored to prevent unauthorized changes.`,
			Recommendation: `Ensure that log alerts exist for firewall rule changes.
			- https://cloud.google.com/logging/docs/logs-based-metrics/`,
		},
	},
	categoryLogging + "/vpcNetworkLogging": {
		Score: 0.3,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `VPC Network Logging
			- Ensures that logging and log alerts exist for VPC network changes
			- Project Ownership is the highest level of privilege on a project, any changes in VPC network should be heavily monitored to prevent unauthorized changes.`,
			Recommendation: `Ensure that log alerts exist for VPC network changes.
			- https://cloud.google.com/logging/docs/logs-based-metrics/`,
		},
	},
	categoryLogging + "/vpcNetworkRouteLogging": {
		Score: 0.3,
		Tag:   []string{"hipaa"},
		Recommend: recommend{
			Risk: `VPC Network Route Logging
			- Ensures that logging and log alerts exist for VPC network route changes
			- Project Ownership is the highest level of privilege on a project, any changes in VPC network route should be heavily monitored to prevent unauthorized changes.`,
			Recommendation: `Ensure that log alerts exist for VPC network route changes.
			- https://cloud.google.com/logging/docs/logs-based-metrics/`,
		},
	},

	categorySQL + "/anyHostRootAccess": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Any Host Root Access
			- Ensures SQL instances root user cannot be accessed from any host
			- Root access for SQL instance should only be allowed from whitelisted IPs to ensure secure access only from trusted entities.`,
			Recommendation: `Ensure that root access for SQL instances are not allowed from any host.
			- https://cloud.google.com/sql/docs/mysql/create-manage-users`,
		},
	},
	categorySQL + "/dbAutomatedBackups": {
		Score: 0.6,
		Tag:   []string{"reliability"},
		Recommend: recommend{
			Risk: `DB Automated Backups
			- Ensures automated backups are enabled for SQL instances
			- Google provides a simple method of backing up SQL instances at a regular interval.
			- This should be enabled to provide an option for restoring data in the event of a database compromise or hardware failure.`,
			Recommendation: `Ensure that all database instances are configured with automatic backups enabled.
			- https://cloud.google.com/sql/docs/mysql/instance-settings`,
		},
	},
	categorySQL + "/dbMultiAz": {
		Score: 0.3,
		Tag:   []string{"reliability"},
		Recommend: recommend{
			Risk: `DB Multiple AZ
			- Ensures that SQL instances have a failover replica to be cross-AZ for high availability
			- Creating SQL instances in with a single AZ creates a single point of failure for all systems relying on that database.
			- All SQL instances should be created in multiple AZs to ensure proper failover.`,
			Recommendation: `Ensure that all database instances have a DB replica enabled in a secondary AZ.
			- https://cloud.google.com/sql/docs/mysql/instance-settings`,
		},
	},
	categorySQL + "/dbPubliclyAccessible": {
		Score: 0.8,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `DB Publicly Accessible
			- Ensures that SQL instances do not allow public access
			- Unless there is a specific business requirement, SQL instances should not have a public endpoint and should only be accessed from within a VPC.`,
			Recommendation: `Ensure that SQL instances are configured to prohibit traffic from the public 0.0.0.0 global IP address.
			- https://cloud.google.com/sql/docs/mysql/authorize-networks`,
		},
	},
	categorySQL + "/dbRestorable": {
		Score: 0.3,
		Tag:   []string{"pci", "reliability"},
		Recommend: recommend{
			Risk: `DB Restorable
			- Ensures SQL instances can be restored to a recent point
			- Google will maintain a point to which the database can be restored.
			- This point should not drift too far into the past, or else the risk of irrecoverable data loss may occur.`,
			Recommendation: `Ensure all database instances are configured with automatic backups and can be restored to a recent point with binary logging enabled.
			- https://cloud.google.com/sql/docs/mysql/instance-settings`,
		},
	},
	categorySQL + "/dbSSLEnabled": {
		Score: 0.3,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `Database SSL Enabled
			- Ensures SQL databases have SSL enabled
			- Enabling SSL ensures that the sensitive data being transferred from the database is encrypted.`,
			Recommendation: `Ensure that SSL is enabled on all SQL databases.
			- https://cloud.google.com/sql/docs/mysql/instance-settings`,
		},
	},

	categoryStorage + "/bucketAllUsersPolicy": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Storage Bucket All Users Policy
			- Ensures Storage bucket policies do not allow global write, delete, or read permissions
			- Storage buckets can be configured to allow the global principal to access the bucket via the bucket policy.
			- This policy should be restricted only to known users or accounts.`,
			Recommendation: `Ensure that each storage bucket is configured so that no member is set to allUsers or allAuthenticatedUsers.
			- https://cloud.google.com/storage/docs/access-control/iam`,
		},
	},
	categoryStorage + "/bucketLogging": {
		Score: 0.3,
		Tag:   []string{"hipaa"},
		Recommend: recommend{
			Risk: `Bucket Logging
			- Ensures object logging is enabled on storage buckets
			- Storage bucket logging helps maintain an audit trail of access that can be used in the event of a security incident.`,
			Recommendation: `Bucket Logging can only be enabled by using the Command Line Interface and the log bucket must already be created.
			- Use this command to enable Logging:
			- gsutil logging set on -b gs://[LOG_BUCKET_NAME] -o AccessLog \ gs://[BUCKET_NAME]
			- https://cloud.google.com/storage/docs/access-logs`,
		},
	},
	categoryStorage + "/bucketVersioning": {
		Score: 0.3,
		Tag:   []string{"reliability"},
		Recommend: recommend{
			Risk: `Bucket Versioning
			- Ensures object versioning is enabled on storage buckets
			- Object versioning can help protect against the overwriting of objects or data loss in the event of a compromise.`,
			Recommendation: `Bucket Versioning can only be enabled by using the Command Line Interface, use this command to enable Versioning:
			- gsutil versioning set on gs://[BUCKET_NAME]
			- https://cloud.google.com/storage/docs/using-object-versioning`,
		},
	},

	categoryVPCNetwork + "/defaultVpcInUse": {
		Score: 0.3,
		Tag:   []string{"pci"},
		Recommend: recommend{
			Risk: `Default VPC In Use
			- Determines whether the default VPC is being used for launching VM instances
			- The default VPC should not be used in order to avoid launching multiple services in the same network which may not require connectivity.
			- Each application, or network tier, should use its own VPC.`,
			Recommendation: `Move resources from the default VPC to a new VPC created for that application or resource group.
			- https://cloud.google.com/vpc/docs/vpc`,
		},
	},
	categoryVPCNetwork + "/excessiveFirewallRules": {
		Score: 0.3,
		Tag:   []string{"pci"},
		Recommend: recommend{
			Risk: `Excessive Firewall Rules
			- Determines if there are an excessive number of firewall rules in the account
			- Keeping the number of firewall rules to a minimum helps reduce the attack surface of an account.
			- Rather than creating new rules with the same rules for each project, common rules should be grouped under the same firewall rule.
			- For example, instead of adding port 22 from a known IP to every firewall rule, create a single "SSH" firewall rule which can be used on multiple instances.`,
			Recommendation: `Limit the number of firewall rules to prevent accidental authorizations
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/flowLogsEnabled": {
		Score: 0.3,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `Flow Logs Enabled
			- Ensures VPC flow logs are enabled for traffic logging
			- VPC flow logs record all traffic flowing in to and out of a VPC.
			- These logs are critical for auditing and review after security incidents.`,
			Recommendation: `Enable VPC flow logs for each VPC subnet
			- https://cloud.google.com/vpc/docs/using-flow-logs`,
		},
	},
	categoryVPCNetwork + "/multipleSubnets": {
		Score: 0.3,
		Tag:   []string{"reliability"},
		Recommend: recommend{
			Risk: `Multiple Subnets
			- Ensures that VPCs have multiple networks to provide a layered architecture
			- A single network within a VPC increases the risk of a broader blast radius in the event of a compromise.`,
			Recommendation: `Create multiple networks/subnets in each VPC and change the architecture to take advantage of public and private tiers.
			- https://cloud.google.com/vpc/docs/vpc`,
		},
	},
	categoryVPCNetwork + "/openAllPorts": {
		Score: 0.8,
		Tag:   []string{"hipaa", "pci"},
		Recommend: recommend{
			Risk: `Open All Ports
			- Determines if all ports are open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, services should be restricted to known IP addresses.`,
			Recommendation: `Restrict ports to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openCIFS": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open CIFS
			- Determines if UDP port 445 for CIFS is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as CIFS should be restricted to known IP addresses.`,
			Recommendation: `Restrict UDP port 445 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openDNS": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open DNS
			- Determines if TCP or UDP port 53 for DNS is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as DNS should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP and UDP port 53 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openDocker": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Docker
			- Determine if Docker port 2375 or 2376 is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Docker should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP ports 2375 and 2376 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openFTP": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open FTP
			- Determines if TCP port 20 or 21 for FTP is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as FTP should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 20 or 21 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openHadoopNameNode": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Hadoop HDFS NameNode Metadata Service
			- Determines if TCP port 8020 for HDFS NameNode metadata service is open to the public.
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Hadoop/HDFS should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 8020 to known IP addresses for Hadoop/HDFS.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openHadoopNameNodeWebUI": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Hadoop HDFS NameNode WebUI
			- Determines if TCP port 50070 and 50470 for Hadoop/HDFS NameNode WebUI service is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Hadoop/HDFS should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 50070 and 50470 to known IP addresses for Hadoop/HDFS
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openKibana": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Kibana
			- Determines if TCP port 5601 for Kibana is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Kibana should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 5601 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openMySQL": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open MySQL
			- Determines if TCP port 4333 or 3306 for MySQL is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as MySQL should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP ports 4333 and 3306 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openNetBIOS": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open NetBIOS
			- Determines if UDP port 137 or 138 for NetBIOS is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as NetBIOS should be restricted to known IP addresses.`,
			Recommendation: `Restrict UDP ports 137 and 138 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openOracle": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Oracle
			- Determines if TCP port 1521 for Oracle is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Oracle should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP ports 1521 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openOracleAutoDataWarehouse": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Oracle Auto Data Warehouse
			- Determines if TCP port 1522 for Oracle Auto Data Warehouse is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Oracle should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP ports 1522 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openPostgreSQL": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open PostgreSQL
			- Determines if TCP port 5432 for PostgreSQL is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as PostgreSQL should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 5432 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openRDP": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open RDP
			- Determines if TCP port 3389 for RDP is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as RDP should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 3389 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openRPC": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open RPC
			- Determines if TCP port 135 for RPC is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as RPC should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 135 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openSalt": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Salt
			- Determine if TCP ports 4505 or 4506 for the Salt master are open to the public
			- Active Salt vulnerabilities, CVE-2020-11651 and CVE-2020-11652 are exploiting Salt instances exposed to the internet.
			- These ports should be closed immediately.`,
			Recommendation: `Restrict TCP ports 4505 and 4506 to known IP addresses
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openSMBoTCP": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open SMBoTCP
			- Determines if TCP port 445 for Windows SMB over TCP is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SMB should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 445 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openSMTP": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open SMTP
			- Determines if TCP port 25 for SMTP is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SMTP should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 25 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openSQLServer": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open SQLServer
			- Determines if TCP port 1433 or UDP port 1434 for SQL Server is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SQL server should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 1433 and UDP port 1434 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openSSH": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open SSH
			- Determines if TCP port 22 for SSH is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SSH should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 22 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openTelnet": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Telnet
			- Determines if TCP port 23 for Telnet is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Telnet should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 23 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openVNCClient": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open VNC Client
			- Determines if TCP port 5500 for VNC Client is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as VNC Client should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 5500 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openVNCServer": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open VNC Server
			- Determines if TCP port 5900 for VNC Server is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as VNC Server should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 5900 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/privateAccessEnabled": {
		Score: 0.3,
		Tag:   []string{"pci"},
		Recommend: recommend{
			Risk: `Private Access Enabled
			- Ensures Private Google Access is enabled for all Subnets
			- Private Google Access allows VM instances on a subnet to reach Google APIs and services without an IP address.
			- This creates a more secure network for the internal communication.`,
			Recommendation: `1. Enter the VPC Network service.
			2. Enter the VPC.
			3. Select the subnet in question.
			4. Edit the subnet and enable Private Google Access.
			- https://cloud.google.com/vpc/docs/configure-private-google-access`,
		},
	},
}
