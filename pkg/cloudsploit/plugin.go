package cloudsploit

const (
	// CloudSploit Category
	categoryAPI                  = "API"
	categoryBigQuery             = "BigQuery"
	categoryCLB                  = "CLB"
	categoryCloudFunctions       = "Cloud Functions"
	categoryCloudResourceManager = "Resource Manager"
	categoryCompute              = "Compute"
	categoryCryptographicKeys    = "Cryptographic Keys"
	categoryDNS                  = "DNS"
	categoryIAM                  = "IAM"
	categoryKubernetes           = "Kubernetes"
	categoryLogging              = "Logging"
	categoryPubSub               = "Pub/Sub"
	categorySpanner              = "Spanner"
	categorySQL                  = "SQL"
	categoryStorage              = "Storage"
	categoryVPCNetwork           = "VPC Network"
)

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
// key: `{Categor}/{Plugin}`, value: meta
var pluginMap = map[string]pluginMetaData{
	categoryAPI + "/apiKeyApplicationRestriction": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `API Key Application Restriction
			- Ensure there are no unrestricted API keys available within your GCP project.
			- To reduce the risk of attacks, Google Cloud API keys should be restricted only to trusted hosts, HTTP referrers, and Android/iOS mobile applications.`,
			Recommendation: `Ensure that Application restrictions are set for all Google Cloud API Keys.
			- https://cloud.google.com/docs/authentication/api-keys#adding_application_restrictions`,
		},
	},
	categoryAPI + "/apiKeyRotation": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `API Key Rotation
			- Ensure that your Google Cloud API Keys are periodically regenerated.
			- Make sure that your Google API Keys are regenerated regularly to avoid data leaks and unauthorized access through outdated API Keys.`,
			Recommendation: `Ensure that all your Google Cloud API keys are regenerated (rotated) after a specific period.
			- https://cloud.google.com/docs/authentication/api-keys`,
		},
	},
	categoryBigQuery + "/datasetAllUsersPolicy": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Dataset All Users Policy
			- Ensure that BigQuery datasets do not allow public read, write or delete access.
			- Granting permissions to allUsers or allAuthenticatedUsers allows anyone to access the dataset.
			- Such access might not be desirable if sensitive data is being stored in the dataset.`,
			Recommendation: `Ensure that each dataset is configured so that no member is set to allUsers or allAuthenticatedUsers.
			- https://cloud.google.com/bigquery/docs/dataset-access-controls`,
		},
	},
	categoryBigQuery + "/datasetLabelsAdded": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Dataset Labels Added
			- Ensure that all BigQuery datasets have labels added.
			- Labels are a lightweight way to group resources together that are related to or associated with each other.
			- It is a best practice to label cloud resources to better organize and gain visibility into their usage.`,
			Recommendation: `Ensure labels are added to all BigQuery datasets.
			- https://cloud.google.com/bigquery/docs/adding-labels`,
		},
	},
	categoryBigQuery + "/tablesCMKEncrypted": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Tables CMK Encrypted
			- Ensure that BigQuery dataset tables are encrypted using desired encryption protection level.
			- By default Google encrypts all datasets using Google-managed encryption keys. 
			- To have more control over the encryption process of your BigQuery dataset tables you can use Customer-Managed Keys (CMKs).`,
			Recommendation: `Ensure that each BigQuery dataset table has desired encryption level.
			- https://cloud.google.com/bigquery/docs/customer-managed-encryption`,
		},
	},

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
	categoryCloudFunctions + "/cloudFunctionLabelsAdded": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Cloud Function Labels Added
			- Labels are a lightweight way to group resources together that are related to or associated with each other. 
			- It is a best practice to label cloud resources to better organize and gain visibility into their usage.`,
			Recommendation: `Ensure labels are added to all Cloud Functions.
			- https://cloud.google.com/functions/docs/configuring`,
		},
	},
	categoryCloudFunctions + "/httpTriggerRequireHttps": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `HTTP Trigger require HTTPS
			- Ensure that Cloud Functions are configured to require HTTPS for HTTP invocations.
			- You can make your google cloud functions call secure by making sure that they require HTTPS.`,
			Recommendation: `Ensure that your Google Cloud functions always require HTTPS.
			- https://cloud.google.com/functions/docs/writing/http`,
		},
	},
	categoryCloudFunctions + "/ingressAllTrafficDisabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Ingress All Traffic Disabled
			- Ensure that Cloud Functions are configured to allow only internal traffic or traffic from Cloud Load Balancer.
			- You can secure your google cloud functions by implementing network based access control.`,
			Recommendation: `Ensure that your Google Cloud functions do not allow external traffic from the internet.
			- https://cloud.google.com/functions/docs/securing/authenticating`,
		},
	},
	categoryCloudResourceManager + "/computeAllowedExternalIPs": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Compute Allowed External IPs
			- Determine if "Define Allowed External IPs for VM Instances" constraint policy is enabled at the GCP organization level.
			- To reduce exposure to the internet, make sure that not all VM instances are allowed to use external IP addresses.`,
			Recommendation: `Ensure that "Define Allowed External IPs for VM Instances" constraint is enforced to allow you to define the VM instances that are allowed to use external IP addresses.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/detailedAuditLoggingMode": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Detailed Audit Logging Mode
			- Determine if "Detailed Audit Logging Mode" policy is configured at the GCP organization level.
			- Detailed Audit Logging Mode is highly encouraged in coordination with Bucket Lock when seeking compliances such as SEC Rule 17a-4(f), CFTC Rule 1.31(c)-(d), and FINRA Rule 4511(c).`,
			Recommendation: `Ensure that "Detailed Audit Logging Mode" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/disableAutomaticIAMGrants": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disable Automatic IAM Grants
			- Determine if "Disable Automatic IAM Grants for Default Service Accounts" policy is enforced at the organization level.
			- By default, service accounts get the editor role when created. To improve access security, disable the automatic IAM role grant.`,
			Recommendation: `Ensure that "Disable Automatic IAM Grants for Default Service Accounts" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/disableDefaultEncryption": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disable Default Encryption Creation
			- Determine if "Restrict Default Google-Managed Encryption for Cloud SQL Instances" is enforced on the GCP organization level.
			- Google-managed encryption keys for Cloud SQL database instances to enforce the use of Customer-Managed Keys (CMKs) in order to have complete control over database encryption/decryption process.`,
			Recommendation: `Ensure that "Restrict Default Google-Managed Encryption for Cloud SQL Instances" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/disableGuestAttributes": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disable Guest Attributes
			- Determine if "Disable Guest Attributes of Compute Engine Metadata" constraint policy is enabled at the GCP organization level.
			- Guest attributes are used for VM instance configuration. For security reasons, ensure that users cannot configure guest attributes for your VM instances.`,
			Recommendation: `Ensure that "Disable Guest Attributes of Compute Engine Metadata" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/disableIdentityClusterCreation": {
		Score: 0.1,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disable Workload Identity Cluster Creation
			- Determine if "Disable Workload Identity Cluster Creation" policy is enforced at the GCP organization level.
			- To have a better control over service account access, make sure that GKE clusters have Workload Identity feature disabled at the time of creation.`,
			Recommendation: `Ensure that "Disable Workload Identity Cluster Creation" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/disableKeyCreation": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disable Service Account Key Creation
			- Determine if "Disable Service Account Key Creation" policy is enforced at the GCP organization level.
			- User-managed keys can impose a security risk if they are not handled correctly. 
			- To minimize the risk, enable user-managed keys in only specific locations.`,
			Recommendation: `Ensure that "Disable Service Account Key Creation" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/disableKeyUpload": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disable Service Account Key Upload
			- Determine if "Disable Service Account Key Upload" policy is enforced at the GCP organization level.
			- User-managed keys can impose a security risk if they are not handled correctly. 
			- To minimize the risk, enable user-managed keys in only specific locations.`,
			Recommendation: `Ensure that "Disable Service Account Key Upload" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/disableSerialPortAccess": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disable Serial Port Access
			- Determine if "Disable VM serial port access" policy is enforced at the GCP organization level.
			- For security purposes, ensure that serial port access to your VM instances is disabled.`,
			Recommendation: `Ensure that "Disable VM serial port access" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/disableServiceAccountCreation": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disable Service Account Creation
			- Determine if "Disable Service Account Creation" policy is enforced at the GCP organization level.
			- Enforcing the "Disable Service Account Creation" policy allows you to centrally manage your service accounts and reduces the chances of compromised service accounts being used to access your GCP resources.`,
			Recommendation: `Ensure that "Disable Service Account Creation" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/disableVMIPForwarding": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disable VM IP Forwarding
			- Determine if "Restrict VM IP Forwarding" constraint policy is enforced at the GCP organization level.
			- Enforcing the "Restrict VM IP Forwarding" constraint allows you to define the VM instances that can ensble IP forwarding.`,
			Recommendation: `Ensure that "Restrict VM IP Forwarding" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/locationBasedRestriction": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Location-Based Service Restriction
			- Determine if "Resource Location Restriction" is enforced on the GCP organization level.
			- Enforcing the "Resource Location Restriction" constraint allows you to define the locations where your cloud resources can be created.`,
			Recommendation: `Ensure that "Resource Location Restriction" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/requireOsLogin": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Enforce Require OS Login
			- Determine if "Require OS Login" policy is enforced at the GCP organization level.
			- Enabling OS Login at project level will ensure that the SSH keys being used to access your VM instances are mapped with Cloud IAM users.`,
			Recommendation: `Ensure that "Require OS Login" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints'`,
		},
	},
	categoryCloudResourceManager + "/restrictAuthorizedNetworks": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Enforce Restrict Authorized Networks
			- Determine if "Restrict Authorized Networks on Cloud SQL instances" policy is enforced at the GCP organization level.
			- Enforcing "Restrict Authorized Networks on Cloud SQL instances" organization policy, restricts adding authorized networks for unproxied database access to Cloud SQL instances.`,
			Recommendation: `Ensure that "Restrict Authorized Networks on Cloud SQL instances" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/restrictLoadBalancerCreation": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Restrict Load Balancer Creation
			- Determine if "Restrict Load Balancer Creation for Types" is enforced on the GCP organization level.
			- Enforcing the "Restrict Load Balancer Creation for Types" constraint allows you to control which type of load balancers can be created within your organization.`,
			Recommendation: `Ensure that "Restrict Load Balancer Creation for Types" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/restrictSharedVPCSubnetworks": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Restrict Shared VPC Subnetworks
			- Determine if "Restrict Shared VPC Subnetworks" is enforced on the GCP organization level.
			- Enforcing the "Restrict Shared VPC Subnetworks" constraint allows you to define which VPC Shared Subnetworks your resources can use within your GCP organization.`,
			Recommendation: `Ensure that "Restrict Shared VPC Subnetworks" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/restrictVPCPeering": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Restrict VPC Peering
			- Determine if "Restrict VPC Peering" is enforced on the GCP organization level.
			- Enforcing the "Restrict VPC Peering" constraint allows you to define which VPC Networks are allowed to be peered with other networks.`,
			Recommendation: `Ensure that "Restrict VPC Peering" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/restrictVPNPeerIPs": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Restrict VPN Peer IPs
			- Determine if "Restrict VPN Peer IPs" is enforced on the GCP organization level.
			- Enforcing the "Restrict VPN Peer IPs" constraint allows you to control the IP addresses which can be configured as VPN Peers.`,
			Recommendation: `Ensure that "Restrict VPN Peer IPs" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/skipDefaultNetworkCreation": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Skip Default Network Creation
			- Determine if "Skip Default Network Creation" constraint policy is enforces at the GCP organization level.
			- Enforcing the "Skip Default Network Creation" disables the creation of default VPC network on project creation which is recommended if you want to keep some parts of your network private.`,
			Recommendation: `Ensure that "Skip Default Network Creation" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/trustedImageProjects": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Trusted Image Projects
			- Determine if "Define Trusted Image Projects" constraint policy is enforces at the GCP organization level.
			- Enforcing the "Define Trusted Image Projects" allows you to restrict disk image access and ensure that your project members can only create boot disks from trusted images.`,
			Recommendation: `Ensure that "Define Trusted Image Projects" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},
	categoryCloudResourceManager + "/uniformBucketLevelAccess": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Enforce Uniform Bucket-Level Access
			- Determine if "Enforce uniform bucket-level access" policy is enabled at the GCP organization level.
			- Enforcing Uniform Bucket Level Access ensures that access is granted exclusively through Cloud IAM service which is more efficient and secure.`,
			Recommendation: `Ensure that "Enforce uniform bucket-level access" constraint is enforced at the organization level.
			- https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
		},
	},

	categoryCompute + "/VMDisksCMKEncrypted": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `VM Disks CMK Encryption
			- Ensure that Virtual Machine instances are encrypted using customer-managed keys.
			- Google encrypts all disks at rest by default. By using CMKs you can have better control over your disk encryption.`,
			Recommendation: `Ensure that your VM instances have CMK encryption enabled.
			- https://cloud.google.com/compute/docs/disks/customer-supplied-encryption`,
		},
	},
	categoryCompute + "/applicationConsistentSnapshots": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Application Consistent Snapshots
			- Ensure that application consistent snapshots feature is enabled for snapshot schedules.
			- Application consistent snapshots are more reliable because they are created after making sure that current operations are temporarily ceased and any data in memory is flushed to disk.`,
			Recommendation: `Ensure that all disk snapshot schedules are application consistent.
			- https://cloud.google.com/compute/docs/disks/snapshot-best-practices#prepare_for_consistency`,
		},
	},
	categoryCompute + "/automaticRestartEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Instance Automatic Restart Enabled
			- Ensure that Virtual Machine instances have automatic restart feature enabled.
			- Automatic Restart sets the virtual machine restart behavior when an instance is crashed or stopped by the system. 
			- If it is enabled, Google Cloud Compute Engine restarts the instance if it crashes or is stopped.`,
			Recommendation: `Ensure automatic restart is enabled for all virtual machine instances.
			- https://cloud.google.com/compute/docs/instances/setting-instance-scheduling-options#autorestart`,
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
	categoryCompute + "/autoscaleMinCpuUtilization": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Autoscale Minimum CPU Utilization Target
			- Ensure that minimum CPU utilization target is greater or equal than set percentage.
			- The autoscaler treats the target CPU utilization level as a fraction of the average use of all vCPUs over time in the instance group. 
			- If the average utilization of your total vCPUs exceeds the target utilization, the autoscaler adds more VM instances. 
			- If the average utilization of your total vCPUs is less than the target utilization, the autoscaler removes instances.`,
			Recommendation: `Ensure all instance groups have Minimum CPU Utilization greater than or equal to target value.
			- https://cloud.google.com/compute/docs/autoscaler/scaling-cpu`,
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
	categoryCompute + "/deprecatedImages": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Deprecated Images
			- Ensure that Compute instances are not created from deprecated images.
			- Deprecated Compute Disk Images should not be used to create VM instances.`,
			Recommendation: `Ensure that no compute instances are created from deprecated images.
			- https://cloud.google.com/compute/docs/images/image-management-best-practices`,
		},
	},
	categoryCompute + "/diskAutomaticBackupEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disk Automatic Backup Enabled
			- Ensure that Google Compute disks have scheduled snapshots configured.
			- Having scheduled snapshots configured for your disks will periodically backup data from your persistent disks.`,
			Recommendation: `Ensure that all compute disks have a snapshot schedule attached.
			- https://cloud.google.com/compute/docs/disks/scheduled-snapshots`,
		},
	},
	categoryCompute + "/diskInUse": {
		Score: 0.3,
		Tag:   []string{"cost"},
		Recommend: recommend{
			Risk: `Disk In Use
			- Ensure that there are no unused Compute disks.
			- Unused Compute disks should be deleted to prevent accidental exposure of data and to avoid unnecessary billing.`,
			Recommendation: `Delete unused Compute disks.
			- https://cloud.google.com/compute/docs/disks`,
		},
	},
	categoryCompute + "/diskLabelsAdded": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disk Labels Added
			- Ensure that all Compute Disks have labels added.
			- Labels are a lightweight way to group resources together that are related to or associated with each other. 
			- It is a best practice to label cloud resources to better organize and gain visibility into their usage.`,
			Recommendation: `Ensure labels are added to all Compute Disks.
			- https://cloud.google.com/compute/docs/labeling-resources`,
		},
	},
	categoryCompute + "/diskMultiAz": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Disk MultiAz
			- Ensure that Compute disks have regional disk replication feature enabled for high availability.
			- Enabling regional disk replication will allow you to force attach a regional persistent disk to another VM instance in a different zone in the same region in case of a zonal outage.`,
			Recommendation: `Ensure that all Google compute disks have replica zones configured.
			- https://cloud.google.com/compute/docs/disks/high-availability-regional-persistent-disk`,
		},
	},
	categoryCompute + "/diskOldSnapshots": {
		Score: 0.3,
		Tag:   []string{"cost"},
		Recommend: recommend{
			Risk: `Disk Old Snapshots
			- Ensure that Compute disk snapshots are deleted after defined time period.
			- To optimize storage costs, make sure that there are no old disk snapshots in your GCP project.'`,
			Recommendation: `Ensure that there are no snapshots older than specified number of days.
			- https://cloud.google.com/compute/docs/disks/create-snapshots`,
		},
	},
	categoryCompute + "/enableUsageExport": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Enable Usage Export
			- Ensure that setting is configured to export Compute instances usage to Cloud Storage bucket.
			- Compute Engine lets you export detailed reports that provide information about the lifetime and usage of your Compute Engine resources to a Google Cloud Storage bucket using the usage export feature.`,
			Recommendation: `Ensure that Enable Usage Export setting is configured for your GCP project.
			- https://cloud.google.com/compute/docs/logging/usage-export`,
		},
	},
	categoryCompute + "/frequentlyUsedSnapshots": {
		Score: 0.3,
		Tag:   []string{"cost"},
		Recommend: recommend{
			Risk: `Frequently Used Snapshots
			- Ensure that frequently used disks are created from images instead of snapshots to save networking cost.
			- If you are repeatedly using a snapshot in the same zone to create a persistent disk, save networking costs by using the snapshot once and creating an image of that snapshot. 
			- Store this image and use it to create your disk and start a VM instance.`,
			Recommendation: `Ensure that your disk snapshots have images created from them.
			- https://cloud.google.com/compute/docs/disks/snapshot-best-practices#prepare_for_consistency`,
		},
	},
	categoryCompute + "/imageLabelsAdded": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Image Labels Added
			- Ensure that all VM disk images have labels added.
			- Labels are a lightweight way to group resources together that are related to or associated with each other. 
			- It is a best practice to label cloud resources to better organize and gain visibility into their usage.`,
			Recommendation: `Ensure labels are added to all disk images.
			- https://cloud.google.com/compute/docs/labeling-resources`,
		},
	},
	categoryCompute + "/instanceDefaultServiceAccount": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Instance Default Service Account
			- Ensures that compute instances are not configured to use the default service account.
			- Default service account has the editor role permissions.
			- Due to security reasons it should not be used for any instance.`,
			Recommendation: `Make sure that compute instances are not using default service account
			- https://cloud.google.com/compute/docs/access/service-accounts`,
		},
	},
	categoryCompute + "/instanceDeletionProtection": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `VM Instance Deletion Protection
			- Ensure that Virtual Machine instances have deletion protection enabled.
			- VM instances should have deletion protection enabled in order to prevent them for being accidentally deleted.`,
			Recommendation: `Modify VM instances to enable deletion protection
			- https://cloud.google.com/compute/docs/instances/preventing-accidental-vm-deletion`,
		},
	},
	categoryCompute + "/instanceDesiredMachineTypes": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Instance Desired Machine Type
			- Ensures that Virtual Machine instances are of given types.
			- Virtual Machine instance should be of the given types to ensure the internal compliance and prevent unexpected billing charges.`,
			Recommendation: `Stop the Virtual Machine instance, change the machine type to the desired type  and restart the instance.
			- https://cloud.google.com/compute/docs/machine-types`,
		},
	},
	categoryCompute + "/instanceGroupAutoHealing": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Instance Group Auto Healing Enabled
			- Ensure that instance groups have auto-healing enabled for high availability.
			- To improve the availability of your application, configure a health check to verify that the application is responding as expected.`,
			Recommendation: `Ensure autohealing is enabled for all instance groups.
			- https://cloud.google.com/compute/docs/instance-groups/autohealing-instances-in-migs`,
		},
	},
	categoryCompute + "/instanceLabelsAdded": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Instance Labels Added
			- Ensure that all Virtual Machine instances have labels added.
			- Labels are a lightweight way to group resources together that are related to or associated with each other. 
			- It is a best practice to label cloud resources to better organize and gain visibility into their usage.`,
			Recommendation: `Ensure labels are added to all VM instances.
			- https://cloud.google.com/compute/docs/labeling-resources`,
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
	categoryCompute + "/instanceMaintenanceBehavior": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Instance Maintenance Behavior
			- Ensure that "On Host Maintenance" configuration is set to Migrate for VM instances.
			- When Google Compute Engine performs regular maintenance of its infrastructure, it migrates your VM instances to other hardware if you have configured the availability policy for the instance to use live migration. 
			- This prevents your applications from experiencing disruptions during these events.`,
			Recommendation: `Ensure that your Google Compute Engine VM instances are configured to use live migration.
			- https://cloud.google.com/compute/docs/instances/setting-instance-scheduling-options`,
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
	categoryCompute + "/instancePreemptibility": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Instance Preemptibility Disabled
			- Ensure that preemptible Virtual Machine instances do not exist.
			- Preemptible instances are excess Compute Engine capacity, so their availability varies with usage.
			- Compute Engine can terminate preemptible instances if it requires access to these resources for other tasks.`,
			Recommendation: `Ensure that your Google Compute Engine VM instances are not preemptible.
			- https://cloud.google.com/compute/docs/instances/preemptible`,
		},
	},
	categoryCompute + "/instancePublicAccess": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Instance Public Access Disabled
			- Ensures that compute instances are not configured to allow public access.
			- Compute Instances should always be configured behind load balancers instead of having public IP addresses in order to minimize the instance\'s exposure to the internet.`,
			Recommendation: `Modify compute instances and set External IP to None for network interface
			- https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address`,
		},
	},
	categoryCompute + "/instanceTemplateMachineTypes": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Instance Template Machine Type
			- Ensure that Cloud Virtual Machine instance templates are of given types.
			- Virtual Machine instance templates should be of the given types to ensure the internal compliance and prevent unexpected billing charges.`,
			Recommendation: `Ensure that Virtual Machine instance templates are not using undesired machine types.
			- https://cloud.google.com/compute/docs/machine-types`,
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
	categoryCompute + "/osLogin2FAEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `OS Login 2FA Enabled
			- Ensure that Virtual Machines instances have OS logic feature enabled and configured with Two-Factor Authentication.
			- Enable OS login Two-Factor Authentication (2FA) to add an additional security layer to your VM instances.
			- The risk of your VM instances getting attcked is reduced significantly if 2FA is enabled.`,
			Recommendation: `Set enable-oslogin-2fa to true in custom metadata for the instance.
			- https://cloud.google.com/compute/docs/oslogin/setup-two-factor-authentication`,
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
	categoryCompute + "/persistentDisksAutoDelete": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Persistent Disks Auto Delete
			- Ensure that auto-delete is disabled for attached persistent disks.
			- When auto-delete is enabled, the attached persistent disk are deleted with VM instance deletion.
			- In cloud environments, you might want to keep the attached persistent disks even when the associated VM instance is deleted.`,
			Recommendation: `Ensure that auto-delete is disabled for all disks associated with your VM instances.
			- https://cloud.google.com/compute/docs/disks`,
		},
	},
	categoryCompute + "/publicDiskImages": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Public Disk Images
			- Ensure that your disk images are not being shared publicly.
			- To avoid exposing sensitive information, make sure that your virtual machine disk images are not being publicly shared with all other GCP accounts.`,
			Recommendation: `Ensure that your VM disk images are not accessible by allUsers or allAuthenticatedUsers.
			- https://cloud.google.com/compute/docs/images`,
		},
	},
	categoryCompute + "/shieldedVmEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Shielded VM Enabled
			- Ensures that instances are configured with the shielded VM enabled
			- Shielded VM option should be configured to defend against the security attacks on the instances.`,
			Recommendation: `Enable the shielded VM for all the instances for security reasons.
			- https://cloud.google.com/security/shielded-cloud/shielded-vm`,
		},
	},
	categoryCompute + "/snapshotLabelsAdded": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Snapshot Labels Added
			- Ensure that Compute disk snapshots have labels added.
			- Labels are a lightweight way to group resources together that are related to or associated with each other. 
			- It is a best practice to label cloud resources to better organize and gain visibility into their usage.`,
			Recommendation: `Ensure labels are added to all Compute disk snapshots.
			- https://cloud.google.com/compute/docs/labeling-resources`,
		},
	},

	categoryCryptographicKeys + "/keyProtectionLevel": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Key Protection Level
			- Ensure that cryptographic keys have protection level equal to or above desired protection level.
			- Cloud KMS cryptographic keys should be created with protection level set by your organization\'s compliance and security rules.`,
			Recommendation: `Create cryptographic keys according to desired protection level
			- https://cloud.google.com/kms/docs/reference/rest/v1/ProtectionLevel`,
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
	categoryCryptographicKeys + "/kmsPublicAccess": {
		Score: 0.8,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `KMS Public Access
			- Ensures cryptographic keys are not publicly accessible.
			- To prevent exposing sensitive data and information leaks, make sure that your cryptokeys do not allow access from anonymous and public users.`,
			Recommendation: `Ensure that your cryptographic keys are not accessible by allUsers or allAuthenticatedUsers.
			- https://cloud.google.com/kms/docs/reference/permissions-and-roles`,
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
	categoryDNS + "/dnsZoneLabelsAdded": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `DNS Zone Labels Added
			- Ensure Cloud DNS zones have labels added.
			- Labels are a lightweight way to group resources together that are related to or associated with each other. 
			- It is a best practice to label cloud resources to better organize and gain visibility into their usage.`,
			Recommendation: `Ensure labels are added for all managed zones in the cloud DNS service.
			- https://cloud.google.com/dns/docs/zones`,
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
	categoryIAM + "/memberAdmin": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Member Admin
			- Ensure that IAM members do not use primitive roles such as owner, editor or viewer.
			- For best security practices, use only predefined IAM roles and do not use primitive roles to prevent any unauthorized access to your resources.`,
			Recommendation: `Ensure that no IAM member has a primitive role.
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
	categoryIAM + "/serviceAccountTokenCreator": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Service Account Token Creator
			- Ensures that no users have the Service Account Token Creator role.
			- For best security practices, IAM users should not have Service Account Token Creator role.`,
			Recommendation: `Ensure that no IAM user have Service Account Token Creator Role at GCP project level.
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
	categoryKubernetes + "/clusterEncryption": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Cluster Encryption Enabled
			- Ensure that GKE clusters have KMS encryption enabled to encrypt application-layer secrets.
			- Application-layer secrets encryption adds additional security layer to sensitive data such as Kubernetes secrets stored in etcd.`,
			Recommendation: `Ensure that all GKE clusters have the desired application-layer secrets encryption level.
			- https://cloud.google.com/kubernetes-engine/docs/how-to/encrypting-secrets`,
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
	categoryKubernetes + "/integrityMonitoringEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Integrity Monitoring Enabled
			- Ensures all Kubernetes shielded cluster node have integrity monitoring enabled
			- Integrity Monitoring feature automatically monitors the integrity of your cluster nodes.`,
			Recommendation: `Enable Integrity Monitoring feature for your cluster nodes
			- https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes#integrity_monitoring`,
		},
	},
	categoryKubernetes + "/kubernetesAlphaDisabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Kubernetes Alpha Disabled
			- Ensure the GKE Cluster alpha cluster feature is disabled.
			- It is recommended to not use Alpha clusters as they expire after thirty days and do not receive security updates.`,
			Recommendation: `1. Create a new cluster with the alpha feature disabled. 
			2. Migrate all required cluster data from the cluster with alpha to this newly created cluster. 
			3. Delete the engine cluster with alpha enabled.
			- https://cloud.google.com/kubernetes-engine/docs/concepts/alpha-clusters`,
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
	categoryKubernetes + "/nodeEncryption": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Node Encryption Enabled
			- Ensure that GKE cluster nodes are encrypted using desired encryption protection level.
			- Using Customer Managed Keys (CMKs) gives you better control over the encryption/decryption process of your cluster nodes.`,
			Recommendation: `Ensure that all node pools in GKE clusters have the desired encryption level.
			- https://cloud.google.com/security/encryption/default-encryption`,
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
	categoryKubernetes + "/secureBootEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Secure Boot Enabled
			- Ensures all Kubernetes cluster nodes have secure boot feature enabled.
			- Secure Boot feature protects your cluster nodes from malware and makes sure the system runs only authentic software.`,
			Recommendation: `Ensure that Secure Boot feature is enabled for all node pools in your GKE clusters.
			- https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes#secure_boot`,
		},
	},
	categoryKubernetes + "/shieldedNodes": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Shielded Nodes
			- Ensure that shielded nodes setting is enabled for all Kubernetes clusters.
			- Shielded GKE nodes give strong cryptographic identity.
			- This prevents attackers from being able to impersonate a node in your GKE cluster even if the attacker can extract the node credentials.`,
			Recommendation: `Ensure that shielded nodes setting is enabled in your GKE cluster
			- https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes`,
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

	categoryPubSub + "/deadLetteringEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Dead Lettering Enabled
			- Ensure that each Google Pub/Sub subscription is configured to use dead-letter topic.
			- Enabling dead lettering will handle message failures by forwarding undelivered messages to a dead-letter topic that stores the message for later access.`,
			Recommendation: `Ensure that dead letter topics are configured for all your Google Cloud Pub/Sub subscriptions.
			- https://cloud.google.com/pubsub/docs/dead-letter-topics`,
		},
	},
	categoryPubSub + "/topicEncryption": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Topic Encryption Enabled
			- Ensure that Google Pub/Sub topics are encrypted with desired encryption level.
			- Google encrypts all messages in topics by default. 
			- By using CSEK, only the users with the key can access the disk. 
			- Anyone else, including Google, cannot access the disk data.`,
			Recommendation: `Ensure that Cloud Pub/Sub topics are encrypted using CSEK keys
			- https://cloud.google.com/pubsub/docs/encryption`,
		},
	},
	categoryPubSub + "/topicLabelsAdded": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Topic Labels Added
			- Ensure that all Pub/Sub topics have labels added.
			- Labels are a lightweight way to group resources together that are related to or associated with each other. 
			- It is a best practice to label cloud resources to better organize and gain visibility into their usage.`,
			Recommendation: `Ensure labels are added to all Pub/Sub topics.
			- https://cloud.google.com/pubsub/docs/labels`,
		},
	},

	categorySpanner + "/instanceNodeCount": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Spanner Instance Node Count
			- Ensure than node count for Spanner instances is not above allowed count.
			- The number of provisioned Cloud Spanner instance nodes must be under desired limit to avoid reaching the limit and exceeding the set budget.`,
			Recommendation: `Modify Spanner instances to decrease number of nodes
			- https://cloud.google.com/spanner/docs/instances`,
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
	categorySQL + "/mysqlLatestVersion": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `MySQL Latest Version
			- Ensure that MySQL database servers are using the latest major version of MySQL database.
			- To make use of the latest database features and benefit from enhanced performance and security, make sure that your MySQL database instances are using the latest major version of MySQL`,
			Recommendation: `Ensure that all your MySQL database instances are using the latest MYSQL database version.
			- https://cloud.google.com/sql/docs/mysql/db-versions`,
		},
	},
	categorySQL + "/mysqlLocalInfile": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `MySQL Local Infile Disabled
			- Ensures SQL instances for MySQL type does not have local infile flag enabled.
			- SQL instances for MySQL type database provides local_infile flag, which can be used to load data from client or server systems. 
			- It controls the load data statements for database. 
			- Anyone using this server can access any file on the client system. 
			- For security reasons it should be disabled.`,
			Recommendation: `Ensure that local infile flag is disabled for all MySQL instances.
			- https://cloud.google.com/sql/docs/mysql/flags`,
		},
	},
	categorySQL + "/mysqlSlowQueryLog": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `MySQL Slow Query Log Enabled
			- Ensures that MySQL instances have slow query log flag enabled.
			- MySQL instance flag that helps find inefficient or time-consuming SQL queries for MySQL databases.`,
			Recommendation: `Ensure that slow query log flag is enabled for all MySQL instances.
			- https://cloud.google.com/sql/docs/mysql/flags`,
		},
	},
	categorySQL + "/postgresqlLatestVersion": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `PostgreSQL Latest Version
			- Ensure that PostgreSQL database servers are using the latest major version of PostgreSQL database.
			- To make use of the latest database features and benefit from enhanced performance and security, make sure that your PostgreSQL database instances are using the latest major version of PostgreSQL.`,
			Recommendation: `Ensure that all your PostgreSQL database instances are using the latest PostgreSQL database version.
			- https://cloud.google.com/sql/docs/postgres/db-versions`,
		},
	},
	categorySQL + "/postgresqlLogCheckpoints": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `PostgreSQL Log Checkpoints Enabled
			- Ensure that log_checkpoints flag is enabled for PostgreSQL instances.
			- When log_checkpoints flag is enabled, instance checkpoints and restart points are logged in the server log.`,
			Recommendation: `Ensure that all PostgreSQL database instances have log_checkpoints flag and it value is set to on.
			- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag`,
		},
	},
	categorySQL + "/postgresqlLogConnections": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `PostgreSQL Log Connections Flag Enabled
			- Ensures SQL instances for PostgreSQL type have log connections flag enabled.
			- SQL instance for PostgreSQL databases provides log_connections flag. 
			- It is used to log every attempt to connect to the db server. 
			- It is not enabled by default. Enabling it will make sure to log all connection tries`,
			Recommendation: `Ensure that log connections flag is enabled for all PostgreSQL instances.
			- https://cloud.google.com/sql/docs/postgres/flags`,
		},
	},
	categorySQL + "/postgresqlLogDisconnections": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `PostgreSQL Log Disconnections Flag Enabled
			- Ensures SQL instances for PostgreSQL type have log disconnections flag enabled.
			- SQL instance for PostgreSQL databases provides log_disconnections flag. It is used to log every attempt to connect to the DB server. 
			- It is not enabled by default. 
			- Enabling it will make sure to log anyone who disconnects from the instance.`,
			Recommendation: `Ensure that log disconnections flag is enabled for all PostgreSQL instances.
			- https://cloud.google.com/sql/docs/postgres/flags`,
		},
	},
	categorySQL + "/postgresqlLogLockWaits": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `PostgreSQL Log Lock Waits Flag Enabled
			- Ensures SQL instances for PostgreSQL type have log_lock_waits flag enabled.
			- SQL instance for PostgreSQL database provides log_lock_waits flag. 
			- It is not enabled by default. 
			- Enabling it will make sure that log messages are generated whenever a session waits longer than deadlock_timeout to acquire a lock.`,
			Recommendation: `Ensure that log_lock_waits flag is enabled for all PostgreSQL instances.
			- https://cloud.google.com/sql/docs/postgres/flags#config`,
		},
	},
	categorySQL + "/postgresqlLogMinDuration": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `PostgreSQL Log Min Duration Statement
			- Ensures SQL instances for PostgreSQL type have log min duration statement flag disabled.
			- SQL instance for PostgreSQL databases provides log_min_duration_statement flag. 
			- It is used to log the duration of every completed statement. 
			- This should always be disabled as there can be sensitive information as well that should not be recorded in the logs.`,
			Recommendation: `Ensure that log_min_duration_statement flag is disabled for all PostgreSQL instances.
			- https://cloud.google.com/sql/docs/postgres/flags`,
		},
	},
	categorySQL + "/postgresqlLogMinError": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `PostgreSQL Log Min Error Statement
			- Ensures SQL instances for PostgreSQL type have log min error statement flag set to Error.
			- SQL instance for PostgreSQL databases provides log_min_error_statement flag. 
			- It is used to mention/tag that the error messages. 
			- Setting it to Error value will help to find the error messages appropriately.`,
			Recommendation: `Ensure that log_min_error_statement flag is set to Error for all PostgreSQL instances.
			- https://cloud.google.com/sql/docs/postgres/flags`,
		},
	},
	categorySQL + "/postgresqlLogTempFiles": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `PostgreSQL Log Temp Files
			- Ensures SQL instances for PostgreSQL type have log temp files flag enabled.
			- SQL instance for PostgreSQL databases provides log_temp_files flag. 
			- It is used to log the temporary files name and size. It is not enabled by default. 
			- Enabling it will make sure to log names and sizes of all the temporary files that were created during any operation(sort, hashes, query_results etc).`,
			Recommendation: `Ensure that log_temp_files flag is enabled for all PostgreSQL instances.
			- https://cloud.google.com/sql/docs/postgres/flags`,
		},
	},
	categorySQL + "/postgresqlMaxConnections": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `PostgreSQL Max Connections
			- Ensure that max_connections is configured with optimal value for PostgreSQL instances.
			- An optimal value should be set for max_connections (maximum number of client connections) to meet the database workload requirements.
			- If this no value is set for max_connections flag, instance assumes default value which is calculated per instance memory size.`,
			Recommendation: `Ensure that all PostgreSQL database instances have log_checkpoints flag and it value is set to on.
			- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag`,
		},
	},
	categorySQL + "/serverCertificateRotation": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `SSL Certificate Rotation
			- Ensure that server certificates configured for Cloud SQL are rotated before they expire.
			- Server certificates configured for Cloud SQL DB instances should be rotated before they expire to ensure that incoming connections for database instance remain secure.`,
			Recommendation: `Edit Cloud SQL DB instances and rotate server certificates under Connections->MANAGE CERTIFICATES
			- https://cloud.google.com/sql/docs/postgres/configure-ssl-instance?authuser=1#server-certs`,
		},
	},
	categorySQL + "/sqlCMKEncryption": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `SQL CMK Encryption
			- Ensure that Cloud SQL instances are encrypted using Customer Managed Keys (CMKs).
			- By default, your Google Cloud SQL instances are encrypted using Google-managed keys. 
			- To have a better control over the encryption process of your Cloud SQL instances you can use Customer-Managed Keys (CMKs).`,
			Recommendation: `Ensure that all Google Cloud SQL instances have desired encryption level.
			- https://cloud.google.com/sql/docs/sqlserver/cmek`,
		},
	},
	categorySQL + "/sqlContainedDatabaseAuth": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `SQL Contained Database Authentication
			- Ensures SQL instances of SQL Server type have Contained Database Authentication flag disabled.
			- Enabling Contained Database Authentication flag allows users to connect to the database without authenticating a login at the Database Engine level along with other security threats.'`,
			Recommendation: `Ensure that Contained Database Authentication flag is disabled for all SQL Server instances.
			- https://cloud.google.com/sql/docs/sqlserver/flags`,
		},
	},
	categorySQL + "/sqlCrossDbOwnership": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `SQL Cross DB Ownership Chaining
			- Ensures SQL database instances of SQL Server type have cross db ownership chaining flag disabled.
			- SQL databases of SQL Server provide cross DB ownership chaining flag.
			- It is used to configure cross-database ownership chaining for all databases.
			- It is enabled by default and should be disabled for security unless all required.`,
			Recommendation: `Ensure that cross DB ownership chaining flag is disabled for all SQLServer instances.
			- https://cloud.google.com/sql/docs/sqlserver/flags`,
		},
	},
	categorySQL + "/sqlInstanceLabelsAdded": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `SQL Instance Labels Added
			- Ensures SQL database instances have labels added.
			- Labels are a lightweight way to group resources together that are related to or associated with each other.
			- It is a best practice to label cloud resources to better organize and gain visibility into their usage.`,
			Recommendation: `Ensure labels are added for all SQL databases.
			- https://cloud.google.com/sql/docs/mysql/label-instance`,
		},
	},
	categorySQL + "/sqlNoPublicIps": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `SQL No Public IPs
			- Ensure that SQL instances are using private IPs instead of public IPs.
			- Cloud SQL databases should always use private IP addresses which provide improved network security and lower latency.`,
			Recommendation: `Make sure that SQL databases IP addresses setting does not have IP address of PRIMARY type
			- https://cloud.google.com/sql/docs/mysql/configure-private-ip`,
		},
	},
	categorySQL + "/storageAutoIncreaseEnabled": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Storage Auto Increase Enabled
			- Ensure that Cloud SQL DB instances have Automatic Storage Increase feature enabled and desired limit is set for storage increases.
			- When this feature is enabled, Cloud SQL checks your available storage every 30 seconds.
			- If the available storage falls below a threshold size, Cloud SQL automatically and permanently adds additional storage capacity.
			- Setting a limit for automatic storage increase can prevent your instance size from growing too large.`,
			Recommendation: `Edit Cloud SQL instances and enable automatic storage increases feature under storage
			- https://cloud.google.com/sql/docs/mysql/instance-settings?authuser=1#automatic-storage-increase-2ndgen`,
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
	categoryStorage + "/bucketEncryption": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Bucket Encryption
			- Ensure that Cloud Storage buckets have encryption enabled using desired protection level.
			- By default, all storage buckets are encrypted using Google-managed keys.
			- To have better control over how your storage bucktes are encrypted, you can use Customer-Managed Keys (CMKs).`,
			Recommendation: `Ensure that all storage buckets have desired encryption level.
			- https://cloud.google.com/storage/docs/encryption/customer-managed-keys`,
		},
	},
	categoryStorage + "/bucketLabelsAdded": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Bucket Labels Added
			- Ensure that all Cloud Storage buckets have labels added.
			- Labels are a lightweight way to group resources together that are related to or associated with each other.
			- It is a best practice to label cloud resources to better organize and gain visibility into their usage.`,
			Recommendation: `Ensure labels are added to all storage buckets.
			- https://cloud.google.com/storage/docs/using-bucket-labels`,
		},
	},
	categoryStorage + "/bucketLifecycleConfigured": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Bucket Lifecycle Configured
			- Ensure that Cloud Storage buckets are using lifecycle management rules to transition objects between storage classes.
			- Lifecycle management rules allow you to delete buckets at the end of their lifecycle and help optimize your data for storage costs.`,
			Recommendation: `Modify storage buckets and configure lifecycle rules.
			- https://cloud.google.com/storage/docs/managing-lifecycles`,
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
	categoryStorage + "/bucketRetentionPolicy": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Storage Bucket Retention Policy
			- Ensures bucket retention policy is set and locked to prevent deleting or updating of bucket objects or retention policy.
			- Configuring retention policy for bucket prevents accidental deletion as well as modification of bucket objects.
			- This retention policy should also be locked to prevent policy deletion.`,
			Recommendation: `Modify bucket to configure retention policy and lock retention policy.
			- https://cloud.google.com/storage/docs/bucket-lock`,
		},
	},
	categoryStorage + "/bucketUniformAccess": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Bucket Uniform Level Access
			- Ensures that uniform level access is enabled on storage buckets.
			- Uniform level access for buckets can be used for managing access in a simple way.
			- It enables us to use other security features like IAM conditions.`,
			Recommendation: `Make sure that storage buckets have uniform level access enabled
			- https://cloud.google.com/storage/docs/uniform-bucket-level-access#should-you-use`,
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
	categoryVPCNetwork + "/dnsLoggingEnabled": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `VPC DNS Logging Enabled
			- Ensure that All VPC Network has DNS logging enabled.
			- Cloud DNS logging records the queries coming from Compute Engine VMs, GKE containers, or other GCP resources provisioned within the VPC to Stackdriver.`,
			Recommendation: `Create Cloud DNS Server Policy with logging enabled for VPC Networks
			- https://cloud.google.com/dns/docs/monitoring`,
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
	categoryVPCNetwork + "/firewallLoggingMetadata": {
		Score: 0.3,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Firewall Logging Metadata
			- Ensure that VPC Network firewall logging is configured to exclude logging metadata in order to reduce the size of the log files.
			- You can significantly reduce the size of your log files and optimize storage costs by not including metadata.
			- By default, metadata is included in firewall rule log files.`,
			Recommendation: `Ensure that metadata is not included in firewall rule log files.
			- https://cloud.google.com/vpc/docs/firewall-rules-logging`,
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
	categoryVPCNetwork + "/openCassandra": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Cassandra
			- Determines if TCP port 7001 for Cassandra is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Cassandra should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP ports 7001 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openCassandraClient": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Cassandra Client
			- Determines if TCP port 9042 for Cassandra Client is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Cassandra Client should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 9042 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openCassandraInternode": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Cassandra Internode
			- Determines if TCP port 7000 for Cassandra Internode is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Cassandra Internode should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 7000 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openCassandraMonitoring": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Cassandra Monitoring
			- Determines if TCP port 7199 for Cassandra Monitoring is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Cassandra Monitoring should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 7199 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openCassandraThrift": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Cassandra Thrift
			- Determines if TCP port 9160 for Cassandra Thrift is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Cassandra Thrift should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 9160 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openCustomPorts": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Custom Ports
			- Ensure that defined custom ports are not open to public.
			- To prevent attackers from identifying and exploiting the services running on your instances, make sure the VPC Network custom ports are not open to public.`,
			Recommendation: `Ensure that your VPC Network firewall rules do not allow inbound traffic for a range of ports.
			- https://cloud.google.com/vpc/docs/firewalls`,
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
	categoryVPCNetwork + "/openElasticsearch": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Elasticsearch
			- Determines if TCP ports 9200, 9300 for Elasticsearch are open to the public
			- Databases are the placeholders for most sensitive and confidential information in an organization. Allowing Inbound traffic from external IPv4 addresses to the database ports can lead to attacks like DoS, Brute Force, Smurf and reconnaissance.
			- It is a best practice to block public access, and restrict the Inbound traffic from specific addresses and make the connection secure.`,
			Recommendation: `Restrict TCP ports 9200, 9300 to known IP addresses.
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
	categoryVPCNetwork + "/openInternalWeb": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Internal web
			- Determines if internal web port 8080 is open to the public
			- Internal web port 8080 is used for web applications and proxy services.
			- Allowing Inbound traffic from any IP address to TCP port 8080 is vulnerable to exploits like backdoor trojan attacks.
			- It is a best practice to block port 8080 from the public internet.`,
			Recommendation: `Restrict TCP port 8080 to known IP addresses.
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
	categoryVPCNetwork + "/openLDAP": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open LDAP
			- Determines if TCP or UDP port 389 for LDAP is open to the public
			- Allowing Inbound traffic from external IPv4 addresses to LDAP ports can lead to attacks like DoS, Brute Force, Smurf, and reconnaissance.
			- It is a best practice to restrict the Inbound traffic from specific addresses.`,
			Recommendation: `Restrict TCP and UDP port 389 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openLDAPS": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open LDAPS
			- Determines if TCP port 636 for LDAP SSL is open to the public
			- LDAP SSL port 636 is used for Secure LDAP authentication.
			- Allowing Inbound traffic from any IP address to TCP port 636 is vulnerable to DoS attacks.
			- It is a best practice to block port 636 from the public internet.`,
			Recommendation: `Restrict TCP port 636 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openMemcached": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Memcached
			- Determines if TCP or UDP port 11211 for Memcached is open to the public
			- Memcached port 11211 is used for caching system and to reduce response times and the load on components.
			- Allowing inbound traffic from any external IP address on memcached port is vulnerable to DoS attacks.
			- It is a best practice to restrict access from specific IP addresses to port 11211.`,
			Recommendation: `Restrict TCP and UDP port 11211 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openMongo": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open MongoDB
			- Determines if TCP port 27017, 27018 or 27019 for MongoDB is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Mongo should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP ports 27017, 27018 and 27019 to known IP addresses.
			- https://cloud.google.com/vpc/docs/using-firewalls`,
		},
	},
	categoryVPCNetwork + "/openMsSQL": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open MSSQL
			- Determines if TCP port 1433 for MSSQL is open to the public.
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as MSSQL should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 1433 to known IP addresses.
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
	categoryVPCNetwork + "/openRedis": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open Redis
			- Determines if TCP port 6379 for Redis is open to the public
			- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Redis should be restricted to known IP addresses.`,
			Recommendation: `Restrict TCP port 6379 to known IP addresses.
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
	categoryVPCNetwork + "/openSNMP": {
		Score: 0.6,
		Tag:   []string{},
		Recommend: recommend{
			Risk: `Open SNMP
			- Determines if UDP port 161 for SNMP is open to the public
			- SNMP UDP 161 used by various devices and applications for logging events, monitoring and management.
			- Allowing Inbound traffic from any external IP address on port 161 is vulnerable to  DoS attack.
			- It is a best practice to block port 161 completely unless explicitly required.`,
			Recommendation: `Restrict UDP port 161 to known IP addresses.
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
	// "/": {
	// 	Score: 0.3,
	// 	Tag:   []string{},
	// 	Recommend: recommend{
	// 		Risk: `xxx
	// 		- xxx
	// 		- xxx`,
	// 		Recommendation: `xxx
	// 		- https://`,
	// 	},
	// },
	// "/": {
	// 	Score: 0.3,
	// 	Tag:   []string{},
	// 	Recommend: recommend{
	// 		Risk: `xxx
	// 		- xxx
	// 		- xxx`,
	// 		Recommendation: `xxx
	// 		- https://`,
	// 	},
	// },
	// "/": {
	// 	Score: 0.3,
	// 	Tag:   []string{},
	// 	Recommend: recommend{
	// 		Risk: `xxx
	// 		- xxx
	// 		- xxx`,
	// 		Recommendation: `xxx
	// 		- https://`,
	// 	},
	// },
	// "/": {
	// 	Score: 0.3,
	// 	Tag:   []string{},
	// 	Recommend: recommend{
	// 		Risk: `xxx
	// 		- xxx
	// 		- xxx`,
	// 		Recommendation: `xxx
	// 		- https://`,
	// 	},
	// },

}
