/*********************
 Collector - The collector will query Azure APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.

 Arguments:
 - AzureConfig: If using an access key/secret, pass in the config object. Pass null if not.
 - settings: custom settings for the scan. Properties:
 - skip_locations: (Optional) List of locations to skip
 - api_calls: (Optional) If provided, will only query these APIs.
 - Example:
 {
     "skip_locations": ["eastus", "westus"],
     "api_calls": ["storageAccounts:list", "resourceGroups:list"]
 }
 - callback: Function to call when the collection is complete
 *********************/

var async = require('async');
var collectors = require(__dirname + '/index.js');

// Standard calls that contain top-level operations
var calls = {
    resourceGroups: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/resourcegroups?api-version=2019-10-01'
        }
    },
    activityLogAlerts: {
        listBySubscriptionId: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01'
        }
    },
    storageAccounts: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01'
        }
    },
    virtualNetworks: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2020-03-01'
        }
    },
    natGateways: {
        listBySubscription: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/natGateways?api-version=2020-11-01'
        }
    },
    virtualMachines: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2019-12-01'
        }
    },
    snapshots: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/snapshots?api-version=2020-12-01'
        }
    },
    disks: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/disks?api-version=2019-07-01'
        }
    },
    networkSecurityGroups: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2020-03-01'
        }
    },
    networkInterfaces: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2020-11-01'
        }
    },
    vaults: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2019-09-01'
        }
    },
    recoveryServiceVaults: {
        listBySubscriptionId: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.RecoveryServices/vaults?api-version=2016-06-01'
        }
    },
    resources: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/resources?api-version=2019-10-01'
        }
    },
    redisCaches: {
        listBySubscription: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Cache/redis?api-version=2020-06-01'
        }
    },
    managedClusters: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/managedClusters?api-version=2020-03-01'
        }
    },
    networkWatchers: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkWatchers?api-version=2020-03-01'
        }
    },
    policyAssignments: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments?api-version=2019-09-01',
        }
    },
    policyDefinitions: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01'
        }
    },
    webApps: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2019-08-01'
        }
    },
    appServiceCertificates: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Web/certificates?api-version=2019-08-01'
        }
    },
    logProfiles: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/microsoft.insights/logprofiles?api-version=2016-03-01'
        }
    },
    profiles: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Cdn/profiles?api-version=2019-04-15'
        }
    },
    autoProvisioningSettings: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview'
        }
    },
    securityContacts: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview',
            ignoreLocation: true
        }
    },
    subscriptions: {
        listLocations: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/locations?api-version=2020-01-01'
        }
    },
    roleDefinitions: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01'
        }
    },
    managementLocks: {
        listAtSubscriptionLevel: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/locks?api-version=2016-09-01'
        }
    },
    loadBalancers: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/loadBalancers?api-version=2020-03-01'
        }
    },
    users: {
        list: {
            url: 'https://graph.windows.net/myorganization/users?api-version=1.6',
            graph: true
        }
    },
    registries: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.ContainerRegistry/registries?api-version=2019-05-01'
        }
    },
    pricings: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2018-06-01'
        }
    },
    availabilitySets: {
        listBySubscription: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/availabilitySets?api-version=2019-12-01'
        }
    },
    virtualMachineScaleSets: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-12-01'
        }
    },
    autoscaleSettings: {
        listBySubscription: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/microsoft.insights/autoscalesettings?api-version=2015-04-01'
        }
    },
    diagnosticSettingsOperations: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview'
        }
    },
    servers: {
        listSql: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Sql/servers?api-version=2019-06-01-preview'
        },
        listMysql: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.DBforMySQL/servers?api-version=2017-12-01'
        },
        listPostgres: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/servers?api-version=2017-12-01'
        }
    },
    databaseAccounts: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2020-06-01-preview'
        }
    }
};

var postcalls = {
    availabilitySets:{
        listByResourceGroup: {
            reliesOnPath: 'resourceGroups.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/Microsoft.Compute/availabilitySets?api-version=2020-12-01'
        }
    },
    advancedThreatProtection: {
        get: {
            reliesOnPath: 'databaseAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/Microsoft.Security/advancedThreatProtectionSettings/current?api-version=2017-08-01-preview'
        }
    },
    backupProtectedItems: {
        listByVault: {
            reliesOnPath: 'recoveryServiceVaults.listBySubscriptionId',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/backupProtectedItems?api-version=2019-05-13'
        }
    },
    backupPolicies: {
        listByVault: {
            reliesOnPath: 'recoveryServiceVaults.listBySubscriptionId',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/backupPolicies?api-version=2019-05-13'
        }
    },
    serverBlobAuditingPolicies: {
        get: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/auditingSettings?api-version=2017-03-01-preview'
        }
    },
    serverSecurityAlertPolicies: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/securityAlertPolicies?api-version=2017-03-01-preview'
        }
    },
    failoverGroups: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/failoverGroups?api-version=2017-03-01-preview'
        }
    },
    serverAutomaticTuning: {
        get: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/automaticTuning/current?api-version=2020-08-01-preview'
        }
    },
    flowLogs: {
        list: {
            reliesOnPath: 'networkWatchers.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/flowLogs?api-version=2020-11-01'
        }
    },
    virtualNetworkPeerings: {
        list: {
            reliesOnPath: 'virtualNetworks.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/virtualNetworkPeerings?api-version=2020-11-01'
        }
    },
    configurations: {
        listByServer: {
            reliesOnPath: 'servers.listPostgres',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/configurations?api-version=2017-12-01'
        }
    },
    serverAdministrators: {
        list: {
            reliesOnPath: 'servers.listPostgres',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/administrators?api-version=2017-12-01'
        }
    },
    virtualMachines: {
        get: {
            reliesOnPath: 'virtualMachines.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}?api-version=2020-12-01'
        }
    },
    virtualMachineExtensions: {
        list: {
            reliesOnPath: 'virtualMachines.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/extensions?api-version=2019-12-01'
        }
    },
    virtualMachineScaleSetVMs: {
        list: {
            reliesOnPath: 'virtualMachineScaleSets.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/virtualMachines?api-version=2020-12-01'
        }
    },
    virtualNetworkGateways: {
        listByResourceGroup: {
            reliesOnPath: 'resourceGroups.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2020-11-01'
        }
    },
    networkGatewayConnections: {
        listByResourceGroup: {
            reliesOnPath: 'resourceGroups.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/Microsoft.Network/connections?api-version=2020-11-01'
        }
    },
    blobContainers: {
        list: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/blobServices/default/containers?api-version=2019-06-01'
        }
    },
    blobServices: {
        list: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/blobServices?api-version=2019-06-01'
        },
        getServiceProperties: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/blobServices/default?api-version=2019-06-01'
        }
    },
    fileShares: {
        list: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/fileServices/default/shares?api-version=2019-06-01'
        }
    },
    storageAccounts: {
        listKeys: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/listKeys?api-version=2019-06-01',
            post: true
        }
    },
    encryptionProtectors: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/encryptionProtector?api-version=2015-05-01-preview'
        },
    },
    webApps: {
        getAuthSettings: {
            reliesOnPath: 'webApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/config/authsettings/list?api-version=2019-08-01',
            post: true
        },
        listConfigurations: {
            reliesOnPath: 'webApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/config?api-version=2019-08-01'
        }
    },
    endpoints: {
        listByProfile: {
            reliesOnPath: 'profiles.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/endpoints?api-version=2019-04-15'
        },
    },
    vaults: {
        getKeys: {
            reliesOnPath: 'vaults.list',
            properties: ['vaultUri'],
            url: '{vaultUri}keys?api-version=7.0',
            vault: true
        },
        getSecrets: {
            reliesOnPath: 'vaults.list',
            properties: ['vaultUri'],
            url: '{vaultUri}secrets?api-version=7.0',
            vault: true
        }
    },
    databases: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/databases?api-version=2017-10-01-preview'
        },
    },
    serverAzureADAdministrators: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/administrators?api-version=2014-04-01'
        }
    },
    usages: {
        list: {
            reliesOnPath: 'subscriptions.listLocations',
            properties: ['name'],
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/locations/{name}/usages?api-version=2020-03-01'
        }
    },
    firewallRules: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/firewallRules?api-version=2014-04-01'
        }
    },
    managedClusters: {
        getUpgradeProfile: {
            reliesOnPath: 'managedClusters.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/upgradeProfiles/default?api-version=2020-03-01'
        }
    }
};

var tertiarycalls = {
    databaseBlobAuditingPolicies: {
        get: {
            reliesOnPath: 'databases.listByServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/auditingSettings?api-version=2017-03-01-preview'
        }
    },
    diagnosticSettings: {
        listByEndpoint: {
            reliesOnPath: 'endpoints.listByProfile',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview'
        },
        listByKeyVault: {
            reliesOnPath: 'vaults.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview'
        },
        listByLoadBalancer: {
            reliesOnPath: 'loadBalancers.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview'
        },
        listByNetworkSecurityGroup: {
            reliesOnPath: 'networkSecurityGroups.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview'
        }
    },
    backupShortTermRetentionPolicies: {
        listByDatabase: {
            reliesOnPath: 'databases.listByServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/backupShortTermRetentionPolicies?api-version=2017-10-01-preview'
        }
    }
};

var specialcalls = {
    tableService: {
        listTablesSegmented: {
            reliesOnPath: ['storageAccounts.listKeys'],
        }
    },
    fileService: {
        listSharesSegmented: {
            reliesOnPath: ['storageAccounts.listKeys'],
        }
    },
    blobService: {
        listContainersSegmented: {
            reliesOnPath: ['storageAccounts.listKeys'],
        }
    },
    queueService: {
        listQueuesSegmented: {
            reliesOnPath: ['storageAccounts.listKeys'],
        }
    }
};

function parseCollection(path, obj) {
    if (typeof path == 'string') path = path.split('.');
    if (path.length) {
        var localPath = path.shift();
        if (obj[localPath]) {
            return parseCollection(path, obj[localPath]);
        } else {
            return false;
        }
    } else {
        return obj;
    }
}

var collect = function(AzureConfig, settings, callback) {
    // Used to gather info only
    if (settings.gather) {
        return callback(null, calls, postcalls, tertiarycalls, specialcalls);
    }
    
    var helpers = require(__dirname + '/../../helpers/azure/auth.js');
    
    // Login using the Azure config
    helpers.login(AzureConfig, function(loginErr, loginData) {
        if (loginErr) return callback(loginErr);

        var collection = {};

        var processCall = function(obj, cb) {
            var localUrl = obj.url.replace(/\{subscriptionId\}/g, AzureConfig.SubscriptionID);
            helpers.call({
                url: localUrl,
                post: obj.post,
                token: obj.graph ? loginData.graphToken : (obj.vault ? loginData.vaultToken : loginData.token)
            }, cb);
        };

        async.series([
            // Calls - process the simple calls
            function(cb) {
                function processTopCall(collectionObj, service, subCallObj, subCallCb) {
                    processCall(subCallObj, function(processCallErr, processCallData) {
                        helpers.addLocations(subCallObj, service, collectionObj, processCallErr, processCallData);
                        subCallCb();
                    });
                }
                
                async.eachOfLimit(calls, 10, function(callObj, service, callCb) {
                    if (!collection[service]) collection[service] = {};
                    // Loop through sub-calls
                    async.eachOf(callObj, function(subCallObj, one, subCallCb) {
                        // Skip API calls unless required
                        if (settings &&
                            settings.api_calls &&
                            settings.api_calls.indexOf([service, one].join(':')) === -1) return subCallCb();
                        
                        if (!collection[service][one]) collection[service][one] = {};
                        processTopCall(collection[service][one], service, subCallObj, subCallCb);
                    }, function() {
                        callCb();
                    });
                }, function() {
                    cb();
                });
            },

            // Post Calls - secondary calls that rely on calls
            function(cb) {
                function processTopCall(collectionObj, service, subCallObj, subCallCb) {
                    // Loop through original properties
                    var regionsToLoop = parseCollection(subCallObj.reliesOnPath, collection);
                    if (regionsToLoop && Object.keys(regionsToLoop).length) {
                        // Loop through regions
                        async.eachOfLimit(regionsToLoop, 5, function(regionObj, region, regionCb) {
                            if (regionObj && regionObj.data && regionObj.data.length) {
                                if (!collectionObj[region]) collectionObj[region] = {};
                                async.eachLimit(regionObj.data, 10, function(regionData, regionDataCb) {
                                    var localReq = {
                                        url: subCallObj.url,
                                        post: subCallObj.post,
                                        token: subCallObj.token,
                                        graph: subCallObj.graph,
                                        vault: subCallObj.vault
                                    };
                                    // Check and replace properties
                                    if (subCallObj.properties && subCallObj.properties.length) {
                                        subCallObj.properties.forEach(function(propToReplace) {
                                            if (regionData[propToReplace]) {
                                                var re = new RegExp(`{${propToReplace}}`, 'g');
                                                localReq.url = subCallObj.url.replace(re, regionData[propToReplace]);
                                            }
                                        });
                                    }

                                    // Add ID
                                    collectionObj[region][regionData.id] = {};

                                    // Call and process API
                                    processCall(localReq, function(processCallErr, processCallData) {
                                        if (processCallErr) collectionObj[region][regionData.id].err = processCallErr;
                                        if (processCallData) {
                                            if (processCallData.value) {
                                                collectionObj[region][regionData.id].data = processCallData.value;
                                            } else {
                                                collectionObj[region][regionData.id].data = processCallData;
                                            }
                                            helpers.reduceProperties(service, collectionObj[region][regionData.id].data);
                                        }
                                        regionDataCb();
                                    });
                                }, function() {
                                    regionCb();
                                });
                            } else {
                                regionCb();
                            }
                        }, function() {
                            subCallCb();
                        });
                    } else {
                        subCallCb();
                    }
                }
                
                async.eachOfLimit(postcalls, 10, function(callObj, service, callCb) {
                    if (!collection[service]) collection[service] = {};
                    // Loop through sub-calls
                    async.eachOf(callObj, function(subCallObj, one, subCallCb) {
                        if (settings &&
                            settings.api_calls &&
                            settings.api_calls.indexOf([service, one].join(':')) === -1) return subCallCb();
                        
                        if (!collection[service][one]) collection[service][one] = {};
                        processTopCall(collection[service][one], service, subCallObj, subCallCb);
                    }, function() {
                        callCb();
                    });
                }, function() {
                    cb();
                });
            },

            // Tertiary Calls - tertiary calls that rely on secondary calls
            function(cb) {
                function processTopCall(collectionObj, service, subCallObj, subCallCb) {
                    // Loop through original properties
                    var regionsToLoop = parseCollection(subCallObj.reliesOnPath, collection);
                    if (regionsToLoop && Object.keys(regionsToLoop).length) {
                        // Loop through regions
                        async.eachOf(regionsToLoop, function(regionObj, region, regionCb) {
                            if (!collectionObj[region]) collectionObj[region] = {};
                            // Loop through the resources
                            async.eachOfLimit(regionObj, 5, function(resourceObj, resourceId, resourceCb){
                                function processResource(resourceData, resourceDataCb) {
                                    var localReq = {
                                        url: subCallObj.url,
                                        post: subCallObj.post,
                                        token: subCallObj.token,
                                        graph: subCallObj.graph,
                                        vault: subCallObj.vault
                                    };
                                    // Check and replace properties
                                    if (subCallObj.properties && subCallObj.properties.length) {
                                        subCallObj.properties.forEach(function(propToReplace) {
                                            if (resourceData[propToReplace]) {
                                                var re = new RegExp(`{${propToReplace}}`, 'g');
                                                localReq.url = subCallObj.url.replace(re, resourceData[propToReplace]);
                                            }
                                        });
                                    }

                                    // Add ID
                                    collectionObj[region][resourceData.id] = {};

                                    // Call and process API
                                    processCall(localReq, function(processCallErr, processCallData) {
                                        if (processCallErr) collectionObj[region][resourceData.id].err = processCallErr;
                                        if (processCallData) {
                                            if (processCallData.value) {
                                                collectionObj[region][resourceData.id].data = processCallData.value;
                                            } else {
                                                collectionObj[region][resourceData.id].data = processCallData;
                                            }
                                            helpers.reduceProperties(service, collectionObj[region][resourceData.id].data);
                                        }
                                        resourceDataCb();
                                    });
                                }
                                
                                if (Array.isArray(resourceObj)) {
                                    async.eachLimit(resourceObj, 10, function(resourceData, resourceDataCb) {
                                        processResource(resourceData, resourceDataCb);
                                    }, function(){
                                        resourceCb();
                                    });
                                } else {
                                    if (resourceObj && resourceObj.data && resourceObj.data.length) {
                                        async.eachLimit(resourceObj.data, 10, function(resourceData, resourceDataCb) {
                                            processResource(resourceData, resourceDataCb);
                                        }, function() {
                                            resourceCb();
                                        });
                                    } else {
                                        resourceCb();
                                    }
                                }
                            }, function(){
                                regionCb();
                            });
                        }, function() {
                            subCallCb();
                        });
                    } else {
                        subCallCb();
                    }
                }

                async.eachOfLimit(tertiarycalls, 10, function(callObj, service, callCb) {
                    if (!collection[service]) collection[service] = {};
                    // Loop through sub-calls
                    async.eachOf(callObj, function(subCallObj, one, subCallCb) {
                        if (settings &&
                            settings.api_calls &&
                            settings.api_calls.indexOf([service, one].join(':')) === -1) return subCallCb();
                        
                        if (!collection[service][one]) collection[service][one] = {};
                        if (subCallObj.url) {
                            processTopCall(collection[service][one], service, subCallObj, subCallCb);
                        } else {
                            // Go one level deeper
                            async.eachOf(subCallObj, function(innerCallObj, two, innerCb) {
                                if (settings &&
                                    settings.api_calls &&
                                    settings.api_calls.indexOf([service, one, two].join(':')) === -1) return subCallCb();
                                
                                if (!collection[service][one][two]) collection[service][one][two] = {};
                                processTopCall(collection[service][one][two], service, innerCallObj, innerCb);
                            }, function() {
                                subCallCb();
                            });
                        }
                    }, function() {
                        callCb();
                    });
                }, function() {
                    cb();
                });
            },

            // Process special calls with override functions
            function(cb) {
                async.eachOfLimit(specialcalls, 10, function(callObj, service, callCb) {
                    if (!collectors[service]) return callCb();
                    if (!collection[service]) collection[service] = {};
                    async.eachOfLimit(callObj, 1, function(subCallObj, one, subCallCb) {
                        if (settings &&
                            settings.api_calls &&
                            settings.api_calls.indexOf([service, one].join(':')) === -1) return subCallCb();
                        if (!collectors[service][one]) return subCallCb();
                        if (!collection[service][one]) collection[service][one] = {};
                        var reliesOn = {};
                        if (subCallObj.reliesOnPath) {
                            subCallObj.reliesOnPath.forEach(function(path){
                                reliesOn[path] = parseCollection(path, collection);
                            });
                        }
                        collectors[service][one](collection, reliesOn, function(){
                            subCallCb();
                        });
                    }, function(){
                        callCb();
                    });
                }, function() {
                    cb();
                });
            },

            // Finalize
            function() {
                //console.log(JSON.stringify(collection, null,2));
                callback(null, collection);
            }
        ]);
    });
};

module.exports = collect;
