var shared = require(__dirname + '/../shared.js');
var auth = require(__dirname + '/auth.js');
var async = require('async');

const defualyPolicyAssignments = {
    adaptiveApplicationControlsMonitoringEffect: 'AuditIfNotExists',
    diskEncryptionMonitoringEffect: 'AuditIfNotExists',
    endpointProtectionMonitoringEffect: 'AuditIfNotExists',
    identityRemoveExternalAccountWithWritePermissionsMonitoringEffect: 'AuditIfNotExists',
    disableIPForwardingMonitoringEffect: 'AuditIfNotExists',
    jitNetworkAccessMonitoringEffect: 'AuditIfNotExists',
    nextGenerationFirewallMonitoringEffect: 'AuditIfNotExists',
    identityDesignateLessThanOwnersMonitoringEffect: 'AuditIfNotExists',
    systemUpdatesMonitoringEffect: 'AuditIfNotExists',
    systemConfigurationsMonitoringEffect: 'AuditIfNotExists'
};

function addResult(results, status, message, region, resource, custom) {
    // Override unknown results for known error messages
    if (status == 3 && message && typeof message == 'string') {
        var overrideMsg;
        var skipStatusChange = false;

        if (message.indexOf('The requested operation is not implemented') > -1) {
            overrideMsg = 'Azure does not yet support this resource and method in this location.';
        } else if (message.indexOf('The specified account is disabled') > -1) {
            overrideMsg = 'This resource is disabled for this functionality in this location.';
        } else if (message.indexOf('is not supported for the account') > -1) {
            overrideMsg = 'This resource type is not supported for this query.';
        } else if (message.indexOf('ENOTFOUND') > -1) {
            overrideMsg = 'This endpoint is not supported for this resource.';
        } else if (message.indexOf('No registered resource provider found') > -1) {
            overrideMsg = 'Azure does not support this check in this location.';
        } else if (message.indexOf('using Storage Account SAS') > -1) {
            overrideMsg = 'Aqua does not have permission to list storage account keys. For help fixing this error, see: https://bit.ly/2AhlVP0';
            skipStatusChange = true;
        } else if (message.indexOf('list permission on key vault') > -1) {
            overrideMsg = 'Aqua does not have permission to list objects in this Key Vault. For help fixing this error, see: https://bit.ly/3cbpFyL';
            skipStatusChange = true;
        }

        if (overrideMsg) {
            status = skipStatusChange ? status : 0;
            message = overrideMsg;
        }
    }

    results.push({
        status: status,
        message: message,
        region: region || 'global',
        resource: resource || null,
        custom: custom || false
    });
}

function findOpenPorts(ngs, protocols, service, location, results) {
    let found = false;
    var openPrefix = ['*', '0.0.0.0', '0.0.0.0/0', '<nw/0>', '/0', '::/0', 'internet'];

    for (let sGroups of ngs) {
        let strings = [];
        let resource = sGroups.id;
        let securityRules = sGroups.securityRules;
        var sourceFilter;
        for (let securityRule of securityRules) {
            if (!securityRule.properties) continue;
            let sourceAddressPrefix = securityRule.properties['sourceAddressPrefix'];
            let sourceAddressPrefixes = securityRule.properties['sourceAddressPrefixes'];
            if (!sourceAddressPrefixes || !sourceAddressPrefixes.length) {
                sourceAddressPrefixes = [];
            }
            sourceAddressPrefixes.push(sourceAddressPrefix);
            var sourceFound = false;

            for (let source of sourceAddressPrefixes) {
                if (openPrefix.indexOf(source) > -1) {
                    sourceFilter = openPrefix[openPrefix.indexOf(source)];
                    sourceFound = true;
                    break;
                }
            }
            if (sourceFound) {
                for (let protocol in protocols) {
                    let ports = protocols[protocol];
                    for (let port of ports) {
                        if (securityRule.properties['access'] &&
                            securityRule.properties['access'] === 'Allow' &&
                            securityRule.properties['direction'] &&
                            securityRule.properties['direction'] === 'Inbound' &&
                            securityRule.properties['protocol'] &&
                            (securityRule.properties['protocol'] === protocol || securityRule.properties['protocol'] === '*')) {
                            if (securityRule.properties['destinationPortRange']) {
                                if (securityRule.properties['destinationPortRange'].toString().indexOf("-") > -1) {
                                    let portRange = securityRule.properties['destinationPortRange'].split("-");
                                    let startPort = portRange[0];
                                    let endPort = portRange[1];
                                    if (parseInt(startPort) <= port && parseInt(endPort) >= port) {
                                        var string = `Security Rule "` + securityRule['name'] + `": ` + (protocol === '*' ? `All protocols` : protocol.toUpperCase()) +
                                            ` port ` + ports + ` open to ` + sourceFilter;
                                        strings.push(string);
                                        if (strings.indexOf(string) === -1) strings.push(string);
                                        found = true;
                                    }
                                } else if (parseInt(securityRule.properties['destinationPortRange']) === port ) {
                                    var string = `Security Rule "` + securityRule['name'] + `": ` + (protocol === '*' ? `All protocols` : protocol.toUpperCase()) +
                                        (ports === '*' ? ` and all ports` : ` port ` + ports) + ` open to ` + sourceFilter;
                                    if (strings.indexOf(string) === -1) strings.push(string);
                                    found = true;
                                }
                            } else if (securityRule.properties['destinationPortRanges']) {
                                if (securityRule.properties['destinationPortRanges'].indexOf(port.toString()) > -1) {
                                    var string = `Security Rule "` + securityRule['name'] + `": ` + (protocol === '*' ? `All protocols` : protocol.toUpperCase()) +
                                        ` port ` + ports + ` open to ` + sourceFilter;
                                    if (strings.indexOf(string) === -1) strings.push(string);
                                    found = true;
                                } else {
                                    for (let portRange of securityRule.properties['destinationPortRanges']){
                                        if (portRange.toString().indexOf("-") > -1) {
                                            portRange = portRange.split("-");
                                            let startPort = portRange[0];
                                            let endPort = portRange[1];
                                            if (parseInt(startPort) <= port && parseInt(endPort) >= port){
                                                var string = `Security Rule "` + securityRule['name'] + `": ` + (protocol === '*' ? `All protocols` : protocol.toUpperCase()) +
                                                    ` port ` + ports + ` open to ` + sourceFilter;
                                                strings.push(string);
                                                if (strings.indexOf(string) === -1) strings.push(string);
                                                found = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (strings.length) {
            addResult(results, 2,
                'Security group:(' + sGroups.name +
                ') has ' + service + ': ' + strings.join(' and '), location,
                resource);
        }
    }

    if (!found) {
        addResult(results, 0, 'No public open ports found', location);
    }

    return;
}

function checkPolicyAssignment(policyAssignments, param, text, results, location) {
    if (!policyAssignments) return;

    if (policyAssignments.err || !policyAssignments.data) {
        addResult(results, 3,
            'Unable to query for Policy Assignments: ' + shared.addError(policyAssignments), location);
        return;
    }

    if (!policyAssignments.data.length) {
        addResult(results, 0, 'No existing Policy Assignments found', location);
        return;
    }

    const policyAssignment = policyAssignments.data.find((policyAssignment) => {
        return (policyAssignment &&
                policyAssignment.displayName &&
                policyAssignment.displayName.toLowerCase().includes('asc default'));
    });

    if (!policyAssignment) {
        addResult(results, 0,
            'There are no ASC Default Policy Assignments', location);
        return;
    }

    // This check is required to handle a defect in the Azure API that causes
    // unmodified ASC policies to return an empty object for parameters: {}
    // https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PMSZCA4
    if (policyAssignment.parameters &&
        !Object.keys(policyAssignment.parameters).length) {
        addResult(results, 0,
            'There ASC Default Policy Assignment includes all plugins', location,
            policyAssignment.id);
        return;
    }

    const policyAssignmentStatus = (policyAssignment.parameters && policyAssignment.parameters[param] && policyAssignment.parameters[param].value) ||
    defualyPolicyAssignments[param] || '';

    if (!policyAssignmentStatus.length) {
        addResult(results, 0,
            text + ' is no supported', location, policyAssignment.id);
    } else if (policyAssignmentStatus == 'AuditIfNotExists' || policyAssignmentStatus == 'Audit') {
        addResult(results, 0,
            text + ' is enabled', location, policyAssignment.id);
    } else {
        addResult(results, 2,
            text + ' is disabled', location, policyAssignment.id);
    }
}

function checkLogAlerts(activityLogAlerts, conditionResource, text, results, location) {
    if (!activityLogAlerts) return;

    if (activityLogAlerts.err || !activityLogAlerts.data) {
        addResult(results, 3,
            'Unable to query for Activity Alerts: ' + shared.addError(activityLogAlerts), location);
        return;
    }

    if (!activityLogAlerts.data.length) {
        addResult(results, 2, 'No existing Activity Alerts found', location);
        return;
    }

    let alertCreateUpdateEnabled = false;
    let alertDeleteEnabled = false;
    let alertCreateDeleteEnabled = false;
    let subscriptionId;

    for (let res in activityLogAlerts.data) {
        const activityLogAlertResource = activityLogAlerts.data[res];
        subscriptionId = '/subscriptions/' + activityLogAlertResource.id.split('/')[2];

        if (activityLogAlertResource.type &&
            activityLogAlertResource.type.toLowerCase() !== 'Microsoft.Insights/ActivityLogAlerts'.toLowerCase()) continue;

        const allConditions = activityLogAlertResource.condition;

        if (!allConditions || !allConditions.allOf || !allConditions.allOf.length) continue;


        var conditionOperation = allConditions.allOf.filter((d) => {
            return (d.equals && d.equals.toLowerCase().indexOf(conditionResource) > -1);
        });
        if (conditionOperation && conditionOperation.length) {
            allConditions.allOf.forEach(condition => {
                if (condition.field && (condition.field === 'resourceType') && (condition.equals && (condition.equals.toLowerCase() === conditionResource))) {
                    alertCreateDeleteEnabled = (!alertCreateDeleteEnabled && activityLogAlertResource.enabled ? true : alertCreateDeleteEnabled);
                } else if (condition.equals && condition.equals.toLowerCase().indexOf(conditionResource + '/write') > -1) {
                    alertCreateUpdateEnabled = (!alertCreateUpdateEnabled && activityLogAlertResource.enabled ? true : alertCreateUpdateEnabled);
                } else if (condition.equals && condition.equals.toLowerCase().indexOf(conditionResource + '/delete') > -1) {
                    alertDeleteEnabled = (!alertDeleteEnabled && activityLogAlertResource.enabled ? true : alertDeleteEnabled);
                }
            })
        }
    }

    if ((alertCreateDeleteEnabled && alertDeleteEnabled && alertCreateUpdateEnabled) ||
        (alertCreateUpdateEnabled && alertDeleteEnabled) ||
        (alertCreateDeleteEnabled && !alertDeleteEnabled && !alertCreateUpdateEnabled)) {
        addResult(results, 0,
            `Log Alert for ${text} write and delete is enabled`, location, subscriptionId);
    } else if ((alertCreateDeleteEnabled && alertDeleteEnabled) ||
        (alertDeleteEnabled && !alertCreateUpdateEnabled && !alertCreateDeleteEnabled)) {
        addResult(results, 0,
            `Log alert for ${text} delete is enabled`, location, subscriptionId);
        addResult(results, 2,
            `Log alert for ${text} write is not enabled`, location, subscriptionId);
    } else if ((alertCreateDeleteEnabled && alertCreateUpdateEnabled) ||
        (alertCreateUpdateEnabled && !alertCreateDeleteEnabled && !alertDeleteEnabled)) {
        addResult(results, 0,
            `Log alert for ${text} write is enabled`, location, subscriptionId);
        addResult(results, 2,
            `Log Alert for ${text} delete is not enabled`, location, subscriptionId);
    } else {
        addResult(results, 2,
            `Log Alert for ${text} write and delete is not enabled`, location, subscriptionId);
    }
}

function checkAppVersions(webConfigs, results, location, webAppId, checkProp, allowedProp, name, custom) {
    var found = false;
    if (!webConfigs || webConfigs.err || !webConfigs.data) {
        addResult(results, 3,
            'Unable to query App Service: ' + shared.addError(webConfigs),
            location, webAppId);
    } else {
        if (webConfigs.data[0] &&
            webConfigs.data[0][checkProp] &&
            webConfigs.data[0][checkProp] !== '') {
            found = true;
            var version = parseFloat(webConfigs.data[0][checkProp].replace(/[^\d.-]/g, ''));
            var allowedVersion = parseFloat(allowedProp);

            if (Math.fround(version) >= Math.fround(allowedVersion)) {
                addResult(results, 0,
                    `The ${name} version (${webConfigs.data[0][checkProp]}) is the latest version`, location, webAppId, custom);
            } else {
                addResult(results, 2,
                    `The ${name} version (${webConfigs.data[0][checkProp]}) is not the latest version`, location, webAppId, custom);
            }
        }
    }
    return found;
}

function checkServerConfigs(servers, cache, source, location, results, serverType, configProperty, configName) {
    if (!servers) return;

    if (servers.err || !servers.data) {
        addResult(results, 3,
            'Unable to query for ' + serverType + ' Servers: ' + shared.addError(servers), location);
        return;
    }

    if (!servers.data.length) {
        addResult(results, 0, 'No existing ' + serverType + ' Servers found', location);
        return;
    }

    servers.data.forEach(function(server) {
        const configurations = shared.addSource(cache, source,
            ['configurations', 'listByServer', location, server.id]);

        if (!configurations || configurations.err || !configurations.data) {
            addResult(results, 3,
                'Unable to query for ' + serverType + ' Server configuration: ' + shared.addError(configurations), location, server.id);
        } else {
            var configuration = configurations.data.filter(config => {
                return (config.name == configProperty && config.value.toLowerCase() == 'on');
            });

            if (configuration && configuration.length) {
                addResult(results, 0, configName + ' is enabled for the ' + serverType + ' Server configuration', location, server.id);
            } else {
                addResult(results, 2, configName + ' is disabled for the ' + serverType + ' Server configuration', location, server.id);
            }
        }
    });
}

function processCall(config, method, body, baseUrl, resource, callback) {
    var fullUrl = baseUrl.replace('{resource}', resource);

    var params = {
        url: fullUrl,
        body: body,
        token: config.token,
        method: method
    };

    auth.call(params, callback);
}

function remediateOpenPortsHelper( putCall, pluginName, protocols, ports, config, cache, settings, resource, remediation_file, baseUrl, method, actions, errors, callback) {
    var params = {
        properties: {
            securityRules: []
        },
        location: config.region
    };
    // we need this to make sure that invocation of this function call is making this true. it should not be left true from
    // some previous calls.
    config.ruleChanged = false;
    async.each(protocols, function (protocol, ocb) {
        async.eachOf(ports, function (port, p, cb) {
            //var protocol = protocols[p];
            remediateOpenPorts(putCall, pluginName, protocol, port, config, cache, settings, resource, remediation_file, baseUrl, method, params,function (error, action) {
                if (error && (error.length || Object.keys(error).length)) {
                    errors.push(error);
                } else if (action && (action.length || Object.keys(action).length)) {
                    actions.push(action);
                }
                cb();
            });
        }, function() {
            ocb();
        });
    }, function () {
        if (config.ruleChanged) {
            // wait for callback
            remediatePlugin(config, method, params, baseUrl, resource, remediation_file, putCall, pluginName, function (err) {
                if (err) errors.push(err);

                if (errors && errors.length) {
                    remediation_file['post_remediate']['actions'][pluginName]['error'] = errors.join(', ');
                    settings.remediation_file = remediation_file;
                    callback(errors, null);
                } else if (actions && actions.length) {
                    remediation_file['post_remediate']['actions'][pluginName][resource] = actions;
                    settings.remediation_file = remediation_file;
                    callback(null, actions);
                } else {
                    callback('No action taken');
                }
            });
        }
        else {
            callback();
        }
    });
}

function remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, callback) {
    processCall(config, method, body, baseUrl, resource, function(err) {
        if (err) {
            remediation_file['remediate']['actions'][pluginName]['error'] = err;
            return callback(err, null);
        }

        let action = body;

        return callback(null, action);
    })
}

function remediateOpenPorts(putCall, pluginName, protocol, port, config, cache, settings, resource, remediation_file, baseUrl, method, params, cb) {
    var failingPermissions = [];
    var passingSecurityRules = [];
    var sgName;
    if (resource && resource.length) {
        var sgNameArr = resource.split('/');
        sgName = sgNameArr[sgNameArr.length -1];
        config.region = settings.regions[resource];
        params.location = config.region;
    } else {
        return cb('No resource provided');
    }

    if (!config.region) return cb('No region found when parsing resource');
    if (!sgName) return cb('No security group name found when parsing resource');

    var networkSecurityGroups = shared.addSource(cache, {},
        ['networkSecurityGroups', 'listAll', config.region]);

    if (!networkSecurityGroups.data || networkSecurityGroups.err) return cb('Unable to query for network security groups: ' + shared.addError(networkSecurityGroups));

    if (!networkSecurityGroups.data.length) return cb('No network security groups present');

    var securityGroup = networkSecurityGroups.data.find(nsg => {
        return (nsg.name && nsg.name === sgName);
    });

    if (!securityGroup) return cb('The target network security group was not found');

    if (!remediation_file['pre_remediate']['actions'][pluginName][resource] || !remediation_file['pre_remediate']['actions'][pluginName][resource].length) remediation_file['pre_remediate']['actions'][pluginName][resource] = [];
    if (!remediation_file['post_remediate']['actions'][pluginName][resource] || !remediation_file['post_remediate']['actions'][pluginName][resource].length) remediation_file['post_remediate']['actions'][pluginName][resource] = [];
    if (!remediation_file['remediate']['actions'][pluginName][resource]['steps'] || !remediation_file['remediate']['actions'][pluginName][resource]['steps'].length) remediation_file['remediate']['actions'][pluginName][resource]['steps'] = [];
    var passingPermission = true;
    function findPortRange(portToCheck, protocolToCheck, rule) {
        if (portToCheck &&
            portToCheck.toString().indexOf("-") > -1) {
            let portRange = portToCheck.split("-");
            let startPort = portRange[0];
            let endPort = portRange[1];
            if  (parseInt(startPort) <= port && parseInt(endPort) >= port && protocolToCheck && (protocolToCheck === protocol || protocol === '*')) {
                if (passingPermission) {
                    passingPermission = false;
                }
                failingPermissions.push(rule);
            } else {
                if (passingPermission) return;
                passingSecurityRules.push(rule);
            }
        } else if (portToCheck &&
            portToCheck.toString().indexOf(port.toString()) > -1) {
            if (portToCheck <= port && portToCheck >= port && protocolToCheck && (protocolToCheck === protocol || protocol === '*' )) {
                if (passingPermission) {
                    passingPermission = false;
                }
                failingPermissions.push(rule);
            } else {
                if (passingPermission) return;
                passingSecurityRules.push(rule);
            }
        }
    }

    var failingRulePortIndex = {};

    securityGroup.securityRules.forEach(rule => {
        passingPermission = true;
        if (rule.properties['destinationPortRange']) {
            findPortRange(rule.properties['destinationPortRange'], rule.properties.protocol, rule);
        } else if (rule.properties['destinationPortRanges'] && rule.properties['destinationPortRanges'].length) {
            for (let portIndex in rule.properties['destinationPortRanges']) {
                let portToCheck = rule.properties['destinationPortRanges'][portIndex]
                findPortRange(portToCheck, rule.properties.protocol, rule);
                if (!passingPermission) {
                    failingRulePortIndex[rule.name] = portIndex;
                    break;
                }
            }
        }
        if (passingPermission) {
            passingSecurityRules.push(rule);
        }
    });
    if (passingSecurityRules.length){
        for ( var i in passingSecurityRules){
            var foundPass = params.properties.securityRules.findIndex(rule => rule.name === passingSecurityRules[i].name);
            if (foundPass === -1){
                params.properties.securityRules.push(passingSecurityRules[i]);
            }
        }
    }
    if (!failingPermissions.length) {
        return cb();
    }
    else {
        config.ruleChanged = true;
    }

    // because this changed to async need a way to aggregate errors and actions without stopping the whole function
    var errors = [];
    var actions = [];
    var publicIpv4Strings = ['0.0.0.0', '0.0.0.0/0', '*', 'internet', '<nw/0>'];
    var publicIpv6Strings = ['/0', '::/0', '::'];

    // changed this to an async function to avoid the callback already called error(was forEach loop before)
    async.each(failingPermissions,function(failingPermission, fpCb) {
        var spliced = false;
        var openIpRange = false;
        var openIpv6Range = false;
        var localIpExists = false;
        var localIpV6Exists = false;
        var ipv4InputKey = pluginName + 'AzureReplacementIpAddress';
        var ipv6InputKey = pluginName + 'AzureReplacementIpv6Address';
        var sourceAddressArr = [];

        if (failingPermission.properties && (failingPermission.properties.sourceAddressPrefix || failingPermission.properties.sourceAddressPrefixes)) {

            // I had to parse > stringify because it was using the final state instead of the current state of failingPermission.properties
            remediation_file['pre_remediate']['actions'][pluginName][resource].push(JSON.parse(JSON.stringify(failingPermission.properties)));

            if ( failingPermission.properties.sourceAddressPrefixes ) {
                sourceAddressArr = failingPermission.properties.sourceAddressPrefixes;
            }
            if (failingPermission.properties.sourceAddressPrefix) sourceAddressArr.push(failingPermission.properties.sourceAddressPrefix);

            function checkIp(inputKey, ipType, publicString) {
                if (sourceAddressArr.indexOf(publicString) > -1) {

                    //this is if the input specified does not exist in the security rule
                    if (settings.input && settings.input[inputKey] && sourceAddressArr.indexOf(settings.input[inputKey]) === -1) {
                        sourceAddressArr.push(settings.input[inputKey]);
                        sourceAddressArr.splice(sourceAddressArr.indexOf(publicString), 1);

                    // this if the input specified already exists
                    } else if (settings.input && settings.input[inputKey] && sourceAddressArr.indexOf(settings.input[inputKey]) > -1) {
                        ipType === 'ipv4' ? localIpExists = true : localIpV6Exists = true;
                        sourceAddressArr.splice(sourceAddressArr.indexOf(publicString), 1);

                    // this is if there is no input and the failing port is in an array (destinationPortRanges). Will remove the port from the array
                    } else if ((!settings.input || !settings.input[inputKey]) && (failingRulePortIndex[failingPermission.name]) && !spliced) {
                        spliced = true;
                        failingPermission.properties['destinationPortRanges'].splice([failingRulePortIndex[failingPermission.name]], 1);
                        if ( failingPermission.properties['destinationPortRanges'].length === 0 ){
                            sourceAddressArr = [];
                        }
                        // this is if there is no input and the failing port is not an array,we will remove the  public
                        // string. thus in below section nothing will be added in param and this rule will be deleted eventually
                    } else if (!settings.input || !settings.input[inputKey]) {
                        sourceAddressArr.splice(sourceAddressArr.indexOf(publicString), 1);
                    }

                    ipType === 'ipv4' ? openIpRange = true : openIpv6Range = true;
                }
            }

            publicIpv4Strings.forEach(publicv4String => {
                checkIp(ipv4InputKey, 'ipv4', publicv4String)
            });

            // will save a check, can only be v4 or v6 never both.
            if (!openIpRange) {
                publicIpv6Strings.forEach(publicv6String => {
                    checkIp(ipv6InputKey, 'ipv6', publicv6String)
                });
            }

        } else {
            return fpCb();
        }

        if (!openIpv6Range && !openIpRange) {
            // here we need to clear the ip addressprefix changes we made earlier as this rule does not have any violating ips
            if (sourceAddressArr && sourceAddressArr.length && sourceAddressArr.length === 1) {
                failingPermission.properties.sourceAddressPrefix = sourceAddressArr.join(', ');
                if (failingPermission.properties.sourceAddressPrefixes) delete failingPermission.properties.sourceAddressPrefixes;
            } else if (sourceAddressArr && sourceAddressArr.length && sourceAddressArr.length > 1) {
                failingPermission.properties.sourceAddressPrefixes = sourceAddressArr
                if (failingPermission.properties.sourceAddressPrefix) delete failingPermission.properties.sourceAddressPrefix;
            }
            return fpCb();
        }

        if (openIpRange && openIpv6Range) return fpCb('Invalid format, only IP or IPv6 can be remediated at one time');

        // checking if we are modifying the same rule. if so we can add the further changes in same rule,rather than adding it as separate
        var found = params.properties.securityRules.findIndex(rule => rule.name === failingPermission.name);
        // this ensures that the failing security rule actually has an ip address. if not we do not pass it and it gets deleted
        if (sourceAddressArr && sourceAddressArr.length && sourceAddressArr.length === 1) {
            failingPermission.properties.sourceAddressPrefix = sourceAddressArr.join(', ');
            if (failingPermission.properties.sourceAddressPrefixes) delete failingPermission.properties.sourceAddressPrefixes;
            if (found > -1){
                // remove the previous one and add the latest one with new adjustments
                params.properties.securityRules.splice(found, 1);
            }
            params.properties.securityRules.push(failingPermission);
        } else if (sourceAddressArr && sourceAddressArr.length && sourceAddressArr.length > 1) {
            failingPermission.properties.sourceAddressPrefixes = sourceAddressArr
            if (failingPermission.properties.sourceAddressPrefix) delete failingPermission.properties.sourceAddressPrefix;
            if (found > -1){
                // remove the previous one and add the latest one with new adjustments.
                params.properties.securityRules.splice(found, 1);
            }
            params.properties.securityRules.push(failingPermission);
        } else {
            // we are here means there are no source ips at all,remove the rule from the params. It will be deleted.
            if (found > -1){
                params.properties.securityRules.splice(found, 1);
            }
        }
        // Remediation file savings
        if (openIpv6Range && !localIpV6Exists && settings.input && settings.input[ipv6InputKey]) {
            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                'inboundRule': settings.input[ipv6InputKey],
                'action': 'ADDED'
            });
        } else if (openIpv6Range && localIpV6Exists && settings.input && settings.input[ipv6InputKey]) {
            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                'inboundRule': settings.input[ipv6InputKey],
                'action': 'Already Exists'
            });
        }

        if (openIpv6Range) {
            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                'inboundRule': '::/0',
                'action': 'DELETED'
            });
        }

        if (openIpRange && !localIpExists && settings.input && settings.input[ipv4InputKey]) {
            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                'inboundRule': settings.input[ipv4InputKey],
                'action': 'ADDED'
            });

        } else if (openIpRange && localIpExists && settings.input && settings.input[ipv4InputKey]){
            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                'inboundRule': settings.input[ipv4InputKey],
                'action': 'Already Exists'
            });
        }

        if (openIpRange) {
            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                'inboundRule': '0.0.0.0/0',
                'action': 'DELETED'
            });
        }

        actions.push(params);
        fpCb();
    }, function(err) {
        if (errors && errors.length) {
            cb(errors.join(', '));
        } else if (err) {
            cb(err);
        } else {
            cb(null, actions);
        }
    });
}

module.exports = {
    addResult: addResult,
    findOpenPorts: findOpenPorts,
    checkPolicyAssignment: checkPolicyAssignment,
    checkLogAlerts: checkLogAlerts,
    checkAppVersions: checkAppVersions,
    checkServerConfigs: checkServerConfigs,
    remediatePlugin: remediatePlugin,
    processCall: processCall,
    remediateOpenPorts: remediateOpenPorts,
    remediateOpenPortsHelper: remediateOpenPortsHelper
};