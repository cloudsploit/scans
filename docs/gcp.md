# CloudSploit For Google Cloud Platform (GCP)

## Create Security Audit Role

1. Log into your Google Cloud console and "Activate" your Cloud Shell.
1. Create a new file called aqua-security-audit-role.yaml. You can use: ``nano aqua-security-audit-role.yaml``.
1. Copy and paste the following yaml code in the file on your Cloud Shell, press Ctrl + X and type "Y" to save the file.
```   
name: roles/AquaCSPMSecurityAudit
title: Aqua CSPM Security Audit
includedPermissions:
  - cloudkms.cryptoKeys.list
  - cloudkms.keyRings.list
  - cloudsql.instances.list
  - cloudsql.users.list
  - compute.autoscalers.list
  - compute.backendServices.list
  - compute.disks.list
  - compute.firewalls.list
  - compute.healthChecks.list
  - compute.instanceGroups.list
  - compute.instances.getIamPolicy
  - compute.instances.list
  - compute.networks.list
  - compute.projects.get
  - compute.securityPolicies.list
  - compute.subnetworks.list
  - compute.targetHttpProxies.list
  - container.clusters.list
  - dns.managedZones.list
  - iam.serviceAccountKeys.list
  - iam.serviceAccounts.list
  - logging.logMetrics.list
  - logging.sinks.list
  - monitoring.alertPolicies.list
  - resourcemanager.folders.get
  - resourcemanager.folders.getIamPolicy
  - resourcemanager.folders.list
  - resourcemanager.hierarchyNodes.listTagBindings
  - resourcemanager.organizations.get
  - resourcemanager.organizations.getIamPolicy
  - resourcemanager.projects.get
  - resourcemanager.projects.getIamPolicy
  - resourcemanager.projects.list
  - resourcemanager.resourceTagBindings.list
  - resourcemanager.tagKeys.get
  - resourcemanager.tagKeys.getIamPolicy
  - resourcemanager.tagKeys.list
  - resourcemanager.tagValues.get
  - resourcemanager.tagValues.getIamPolicy
  - resourcemanager.tagValues.list
  - storage.buckets.getIamPolicy
  - storage.buckets.list
stage: GA
```
4. Run the following command to create the role, use your Organization Id to create the Role at the Org Level: ``gcloud iam roles create AquaCSPMSecurityAudit --organization=YOUR_ORGANIZATION_ID --file=aqua-security-audit-role.yaml``

## Create Service Account

1. Log into your Google Cloud console and navigate to IAM Admin > Service Accounts.
1. Click on "Create Service Account".
1. Enter "CloudSploit" in the "Service account name", then enter "CloudSploit API Access" in the description.
1. Click on Continue.
1. Select the role: Custom > Aqua CSPM Security Audit.
1. Click on Continue.
1. Click on "Create Key".
1. Leave the default JSON selected.
1. Click on "Create".
1. The key will be downloaded to your machine.
1. Open the JSON key file, in a text editor and copy the Project Id, Client Email and Private Key values into the `index.js` file or move the JSON key file to a safe location; you can reference it in your `config.js` file later.
