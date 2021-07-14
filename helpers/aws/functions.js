var async = require('async');
var regions = require(__dirname + '/regions');
var AWS = require('aws-sdk');
var helpers = require('../shared.js');

function waitForCredentialReport(iam, callback, CREDENTIAL_DOWNLOAD_STARTED) {
    if (!CREDENTIAL_DOWNLOAD_STARTED) {
        iam.generateCredentialReport(function(err, data){
            if ((err && err.code && err.code == 'ReportInProgress') || (data && data.State)) {
                // Okay to query for credential report
                waitForCredentialReport(iam, callback, true);
            } else {
                //CREDENTIAL_REPORT_ERROR = 'Error downloading report';
                //callback(CREDENTIAL_REPORT_ERROR);
                callback('Error downloading report');
            }
        });
    } else {
        var pingCredentialReport = function(pingCb) {
            iam.getCredentialReport(function(getErr, getData) {
                if (getErr || !getData || !getData.Content) {
                    return pingCb('Error waiting for credential report: ' + (getErr ? getErr : 'No data returned from AWS after 60 seconds.'));
                }

                pingCb(null, getData);
            });
        };

        async.retry({times: 20, interval: 3000}, pingCredentialReport, function(reportErr, reportData){
            if (reportErr || !reportData) {
                //CREDENTIAL_REPORT_ERROR = 'Error downloading report';
                //return callback(CREDENTIAL_REPORT_ERROR);
                return callback('Error downloading report');
            }

            //CREDENTIAL_REPORT_DATA = reportData;
            //callback(null, CREDENTIAL_REPORT_DATA);
            callback(null, reportData);
        });
    }
}

function addResult(results, status, message, region, resource, custom){
    // Override unknown results for regions that are opt-in
    if (status == 3 && region && regions.optin.indexOf(region) > -1 && message &&
        (message.indexOf('AWS was not able to validate the provided access credentials') > -1 ||
         message.indexOf('The security token included in the request is invalid') > -1)) {
        results.push({
            status: 0,
            message: 'Region is not enabled',
            region: region,
            resource: resource || null,
            custom: custom || false
        });
    } else {
        results.push({
            status: status,
            message: message,
            region: region || 'global',
            resource: resource || null,
            custom: custom || false
        });
    }
}

function findOpenPorts(groups, ports, service, region, results) {
    var found = false;

    for (var g in groups) {
        var string;
        var openV4Ports = [];
        var openV6Ports = [];
        var resource = `arn:aws:ec2:${region}:${groups[g].OwnerId}:security-group/${groups[g].GroupId}`;

        for (var p in groups[g].IpPermissions) {
            var permission = groups[g].IpPermissions[p];

            for (var k in permission.IpRanges) {
                var range = permission.IpRanges[k];

                if (range.CidrIp === '0.0.0.0/0' && ports[permission.IpProtocol]) {
                    for (var portIndex in ports[permission.IpProtocol]) {
                        var port = ports[permission.IpProtocol][portIndex];
                        if (port.toString().indexOf('-') > -1) {
                            var portRange = port.split('-');
                            var rangeFrom = Number(portRange[0]);
                            var rangeTo = Number(portRange[1]);

                            for (let i = rangeFrom; i <= rangeTo; i++) {
                                if (permission.FromPort <= i && permission.ToPort >= i) {
                                    string = `some of ${permission.IpProtocol.toUpperCase()}:${port}`;
                                    openV4Ports.push(string);
                                    found = true;
                                    break;
                                }
                            }
                        } else {
                            port = Number(port);
                            if (permission.FromPort <= port && permission.ToPort >= port) {
                                string = `${permission.IpProtocol.toUpperCase()}:${port}`;
                                if (openV4Ports.indexOf(string) === -1) openV4Ports.push(string);
                                found = true;
                            }
                        }
                    }
                }
            }

            for (var l in permission.Ipv6Ranges) {
                var rangeV6 = permission.Ipv6Ranges[l];

                if (rangeV6.CidrIpv6 === '::/0' && ports[permission.IpProtocol]) {
                    for (var portIndexV6 in ports[permission.IpProtocol]) {
                        var portV6 = ports[permission.IpProtocol][portIndexV6];
                        if (portV6.toString().indexOf('-') > -1) {
                            var portRangeV6 = Number(portV6.split('-'));
                            var rangeFromV6 = Number(portRangeV6[0]);
                            var rangeToV6 = portRangeV6[1];

                            for (let i = rangeFromV6; i <= rangeToV6; i++) {
                                if (permission.FromPort <= i && permission.ToPort >= i) {
                                    string = `some of ${permission.IpProtocol.toUpperCase()}:${portV6}`;
                                    openV6Ports.push(string);
                                    found = true;
                                    break;
                                }
                            }
                        } else {
                            portV6 = Number(portV6);
                            if (permission.FromPort <= portV6 && permission.ToPort >= portV6) {
                                var stringV6 = `${permission.IpProtocol.toUpperCase()}:${portV6}`;
                                if (openV6Ports.indexOf(stringV6) === -1) openV6Ports.push(stringV6);
                                found = true;
                            }
                        }
                    }
                }
            }
        }

        if (openV4Ports.length || openV6Ports.length) {
            var resultsString = '';
            if (openV4Ports.length) {
                resultsString = `Security group: ${groups[g].GroupId} (${groups[g].GroupName}) has ${service}:${openV4Ports.join(' and ')} open to 0.0.0.0/0`;
            }

            if (openV6Ports.length) {
                if (resultsString.length) {
                    resultsString = `${resultsString} and ${openV6Ports.join(' and ')} open to ::/0`;
                } else {
                    resultsString = `Security group: ${groups[g].GroupId} (${groups[g].GroupName}) has ${service}:${openV6Ports.join(' and ')} open to ::/0`;
                }
            }

            addResult(results, 2, resultsString,
                region, resource);
        }
    }

    if (!found) {
        addResult(results, 0, 'No public open ports found', region);
    }

    return;
}

function normalizePolicyDocument(doc) {
    /*
    Convert a policy document for IAM into a normalized object that can be used
    by plugins to check policy attributes.
    Returns an array of statements with normalized effect, action, and resource.
    */

    if (typeof doc === 'string') {
        // Need to parse to JSON
        try {
            // Need to urldecode
            if (doc.charAt(0) === '%') doc = decodeURIComponent(doc);
            doc = JSON.parse(doc);
        } catch (e) {
            //Could not parse policy document into JSON
            return false;
        }
    }

    if (typeof doc !== 'object') {
        //Could not parse policy document. Not valid JSON
        return false;
    }

    if (!doc.Statement) return false;

    var statementsToReturn = [];

    // If Statement is an object, convert to array
    if (!Array.isArray(doc.Statement)) doc.Statement = [doc.Statement];

    for (var s in doc.Statement) {
        var statement = doc.Statement[s];

        if (!statement.Effect || !statement.Effect.length ||
            !statement.Action || !statement.Action.length) {
            break;
        }

        if (typeof statement.Effect !== 'string') break;

        if (!Array.isArray(statement.Action)) statement.Action = [statement.Action];
        if (statement.Resource && !Array.isArray(statement.Resource)) statement.Resource = [statement.Resource];

        statementsToReturn.push(statement);
    }

    return statementsToReturn;
}

function globalPrincipal(principal) {
    if (!principal) return false;

    if (typeof principal === 'string' && principal === '*') {
        return true;
    }

    var awsPrincipals = principal.AWS;
    if (!Array.isArray(awsPrincipals)) {
        awsPrincipals = [awsPrincipals];
    }

    if (awsPrincipals.indexOf('*') > -1 ||
        awsPrincipals.indexOf('arn:aws:iam::*') > -1) {
        return true;
    }

    return false;
}

function userGlobalAccess(statement, restrictedPermissions) {
    if (statement.Effect && statement.Effect === 'Allow' &&
        statement.Action && restrictedPermissions.some(permission=> statement.Action.includes(permission))) {
        return true;
    }
    
    return false;
}

function crossAccountPrincipal(principal, accountId, fetchPrincipals) {

    if (typeof principal === 'string' &&
        /^[0-9]{12}$/.test(principal) &&
        principal !== accountId) {
        if (fetchPrincipals) return [principal];
        return true;
    }

    var awsPrincipals = principal.AWS;
    if (!Array.isArray(awsPrincipals)) {
        awsPrincipals = [awsPrincipals];
    }

    var principals = [];

    for (var a in awsPrincipals) {
        if (/^arn:aws:(iam|sts)::[0-9]{12}.*/.test(awsPrincipals[a]) &&
            awsPrincipals[a].indexOf(accountId) === -1) {
            if (!fetchPrincipals) return true;
            principals.push(awsPrincipals[a]);
        }
    }

    if (fetchPrincipals) return principals;
    return false;
}

function hasFederatedUserRole(policyDocument) {
    // true iff every statement refers to federated user access 
    for (let statement of policyDocument) {
        if (statement.Action &&
            !statement.Action.includes('sts:AssumeRoleWithSAML') &&
            !statement.Action.includes('sts:AssumeRoleWithWebIdentity')){
            return false;
        }
    }
    return true;
}

function extractStatementPrincipals(statement) {
    let response = [];
    if (statement.Principal) {
        let principal = statement.Principal;
        
        if (typeof principal === 'string') {
            return [principal];
        }

        if (!principal.AWS) return response;
        
        var awsPrincipals = principal.AWS;
        if (!Array.isArray(awsPrincipals)) {
            awsPrincipals = [awsPrincipals];
        }

        response.push.apply(response, awsPrincipals);
    }

    return response;
}

function getDenyPermissionsMap(statements, excludeStatementId) {
    let permissionsMap = {};

    for (let statement of statements) {
        if ((statement.Sid && statement.Sid == excludeStatementId) || (statement.Effect && statement.Effect.toUpperCase() !== 'DENY')) continue;

        let principals = extractStatementPrincipals(statement);
        principals.forEach(principal => {
            let permissionsObj = JSON.parse(JSON.stringify(getDenyActionResourceMap([statement])));
            if (permissionsMap[principal]) permissionsMap[principal] = {...permissionsMap[principal], ...permissionsObj};
            else permissionsMap[principal] = permissionsObj;
        });
    }

    return permissionsMap;
}

function getDenyActionResourceMap(statements, excludeStatementId) {
    let denyActionResourceMap = {};
    for (let statement of statements) {
        if (statement.Sid && statement.Sid != excludeStatementId &&
            statement.Effect && statement.Effect == 'Deny' &&
            statement.Resource && statement.Resource.length &&
            statement.Action && statement.Action.length) {
            statement.Action.forEach(action => {
                if (denyActionResourceMap[action]) denyActionResourceMap[action].push.apply(denyActionResourceMap[action], statement.Resource);
                else denyActionResourceMap[action] = statement.Resource;
            });
        }
    }

    return denyActionResourceMap;
}

function filterDenyPermissionsByPrincipal(permissionsMap, principal) {
    let response = {};
    Object.keys(permissionsMap).forEach(key => {
        if (matchKeys(key, principal)) {
            Object.keys(permissionsMap[key]).forEach(action => {
                if (response[action]) response[action].push.apply(response[action], permissionsMap[key][action]);
                else response[action] = permissionsMap[key][action];
            });
        }
    });
    return response;
}

function isValidCondition(statement, allowedConditionKeys, iamConditionOperators, fetchConditionPrincipals, accountId) {
    if (statement.Condition && statement.Effect) {
        var effect = statement.Effect;
        var values = [];
        for (var operator of Object.keys(statement.Condition)) {
            var defaultOperator = operator;
            if (operator.includes(':')) defaultOperator = operator.split(':')[1];

            var subCondition = statement.Condition[operator];
            for (var key of Object.keys(subCondition)) {
                let keyLower = key.toLowerCase();
                if (!allowedConditionKeys.some(conditionKey => keyLower.includes(conditionKey.toLowerCase()))) return false;
                var value = subCondition[key];
                if (iamConditionOperators.string[effect].includes(defaultOperator) ||
                iamConditionOperators.arn[effect].includes(defaultOperator)) {
                    if (keyLower === 'kms:calleraccount' && typeof value === 'string' && effect === 'Allow' &&  value === accountId) {
                        values.push(value);
                        return values;
                    } 
                    if (!value.length || value === '*') return false;
                    else if (/^[0-9]{12}$/.test(value) || /^arn:aws:(iam|sts)::.+/.test(value)) values.push(value);
                } else if (defaultOperator === 'Bool') {
                    if ((effect === 'Allow' && !value) || effect === 'Deny' && value) return false;
                } else if (iamConditionOperators.ipaddress[effect].includes(defaultOperator)) {
                    if (value === '0.0.0.0/0' || value === '::/0') return false;
                } else return false;
            }
        }
        if (fetchConditionPrincipals) return values;
    }

    return true;
}

function isEffectivePolicyStatement(statement, denyActionResourceMap) {
    let statementActionResourceMap = {};
    if (statement.Action && statement.Resource) {
        for (let action of statement.Action) {
            statementActionResourceMap[action] = statement.Resource;
        }
    }

    for (let action of Object.keys(statementActionResourceMap)) {
        for (let key of Object.keys(denyActionResourceMap)) {
            if (matchKeys(key, action)) {
                var deniedResources = [];
                for (let stmResource of statementActionResourceMap[action]) {
                    if (denyActionResourceMap[key].find(deniedResource => matchKeys(deniedResource, stmResource))) deniedResources.push(stmResource);
                }

                statementActionResourceMap[action] = statementActionResourceMap[action].filter(resource => !deniedResources.includes(resource));
            }
        }

        if (statementActionResourceMap[action].length) return true;
    }

    return false;
}

function isEffectiveStatement(statement, denyPermissionsMap) {
    var principals = extractStatementPrincipals(statement);

    for (let principal of principals) {
        let denyActionResourceMap = filterDenyPermissionsByPrincipal(denyPermissionsMap, principal);
        if (isEffectivePolicyStatement(statement, denyActionResourceMap)) return true;
    }

    return false;
}

function matchKeys(first, second) {
    if (!first.length && !second.length) return true;

    if (first.length > 1 && first[0] == '*' && !second.length) return false;

    if ((first.length > 1 && first[0] == '?') || (first.length && second.length && first[0] == second[0])) return matchKeys(first.slice(1), second.slice(1));

    if (first.length && first[0] == '*') {
        return matchKeys(first.slice(1), second) || matchKeys(first,second.slice(1));
    }

    return false;
}

function defaultRegion(settings) {
    if (settings.govcloud) return 'us-gov-west-1';
    if (settings.china) return 'cn-north-1';
    return 'us-east-1';
}

function defaultPartition(settings) {
    if (settings.govcloud) return 'aws-us-gov';
    if (settings.china) return 'aws-cn';
    return 'aws';
}

function getS3BucketLocation(cache, region, bucketName) {
    var getBucketLocation = helpers.addSource(cache, {},
        ['s3', 'getBucketLocation', region, bucketName]);

    if (getBucketLocation && getBucketLocation.data) {
        if (getBucketLocation.data.LocationConstraint) return getBucketLocation.data.LocationConstraint;
        else return 'us-east-1';
    }
    return 'global';
}

function remediatePlugin(config, call, params, callback) {
    var service = call.split(':')[0];
    var callKey = call.split(':')[1];
    var executor = new AWS[service](config);

    var executorCb = function(err, data) {
        if (err) {
            return callback(err, null);
        } else {
            return callback(null, data);
        }
    };

    executor[callKey](params, executorCb);
}

function nullArray(object) {
    for (var key in object) {
        if (Array.isArray(object[key]) && !object[key].length) {
            object[key] = null;
        }
    }
    return object;
}

let divideArray = function(array, size) {
    var arrayOfArrays = [];
    while (array.length > 0) {
        arrayOfArrays.push(array.splice(0, size));
    }
    return arrayOfArrays;
};

function getEncryptionLevel(kmsKey, encryptionLevels) {
    if (kmsKey.Origin) {
        if (kmsKey.Origin === 'AWS_KMS') {
            if (kmsKey.KeyManager) {
                if (kmsKey.KeyManager === 'AWS') {
                    return encryptionLevels.indexOf('awskms');
                }
                if (kmsKey.KeyManager === 'CUSTOMER') {
                    return encryptionLevels.indexOf('awscmk');
                }
            }
        }
        if (kmsKey.Origin === 'EXTERNAL') {
            return encryptionLevels.indexOf('externalcmk');
        }
        if (kmsKey.Origin === 'AWS_CLOUDHSM') {
            return encryptionLevels.indexOf('cloudhsm');
        }
    }

    return encryptionLevels.indexOf('none');
}

function remediatePasswordPolicy(putCall, pluginName, remediation_file, passwordKey, config, cache, settings, resource, input, callback) {
    config.region = defaultRegion({});
    var params;
    var getAccountPasswordPolicy = helpers.addSource(cache, {},
        ['iam', 'getAccountPasswordPolicy', config.region]);

    if (!getAccountPasswordPolicy) return callback('No data found');

    let createPolicyInput = pluginName + 'CreatePolicy';

    if ((getAccountPasswordPolicy.err ||
        !getAccountPasswordPolicy.data || !Object.keys(getAccountPasswordPolicy.data).length) && (settings.input && settings.input[createPolicyInput])) {
        remediation_file['pre_remediate']['actions'][pluginName][resource] = null;
        params = {
            HardExpiry: true,
            MaxPasswordAge: '179',
            MinimumPasswordLength: '14',
            PasswordReusePrevention: '24',
            RequireLowercaseCharacters: true,
            RequireNumbers: true,
            RequireSymbols: true,
            RequireUppercaseCharacters: true
        };
        if (input && input[passwordKey]) params[passwordKey] = input[passwordKey];
    } else if (getAccountPasswordPolicy.data && Object.keys(getAccountPasswordPolicy.data).length){
        params = getAccountPasswordPolicy.data;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = params;

        if (input && input[passwordKey]) params[passwordKey] = input[passwordKey];
    } else {
        return callback('No previous policy found');
    }
    // needed because this gets passed in the get call but breaks the put call
    if (params['ExpirePasswords']) delete params['ExpirePasswords'];

    // passes the config, put call, and params to the remediate helper function
    remediatePlugin(config, putCall[0], params, function(err) {
        if (err) {
            remediation_file['remediate']['actions'][pluginName]['error'] = err;
            return callback(err, null);
        }

        let action = params;
        action.action = putCall;

        remediation_file['post_remediate']['actions'][pluginName][resource] = action;
        remediation_file['remediate']['actions'][pluginName][resource] = {
            'Action': 'Enabled'
        };
        settings.remediation_file = remediation_file;
        return callback(null, action);
    });
}

function remediateOpenPorts(putCall, pluginName, protocol, port, config, cache, settings, resource, remediation_file, cb) {
    if (resource && resource.length) {
        var sgId = resource.split('/')[1];
        config.region = resource.split(':')[3];
    } else {
        return cb('No resource provided');
    }

    if (!config.region) return cb('No region found when parsing resource');
    if (!sgId) return cb('No security group name found when parsing resource');


    var describeSecurityGroups = helpers.addSource(cache, {},
        ['ec2', 'describeSecurityGroups', config.region]);

    if (!describeSecurityGroups.data || describeSecurityGroups.err) return cb('Unable to query for security groups: ' + helpers.addError(describeSecurityGroups));

    if (!describeSecurityGroups.data.length) return cb('No security groups present');

    var securityGroup = describeSecurityGroups.data.find(group => {
        return (group.GroupId && group.GroupId === sgId);
    });

    if (!securityGroup) return cb('The target security group was not found');

    remediation_file['pre_remediate']['actions'][pluginName][resource] = [];
    remediation_file['post_remediate']['actions'][pluginName][resource] = [];
    remediation_file['remediate']['actions'][pluginName][resource]['steps'] = [];
    var failingPermissions = securityGroup.IpPermissions.filter(permission => {
        return (permission.FromPort && permission.FromPort <= port && permission.ToPort && permission.ToPort >= port && permission.IpProtocol && permission.IpProtocol === protocol);
    });
    if (!failingPermissions.length) return cb();
    // because this changed to async need a way to aggregate errors and actions without stopping the whole function
    var errors = [];
    var actions = [];
    // changed this to an async function to avoid the callback already called error(was forEach loop before)
    async.each(failingPermissions,function(failingPermission, fpCb) {
        var openIpRange = false;
        var openIpv6Range = false;
        var finalIpRanges = [];
        var finalIpv6Ranges = [];
        var localIpExists = false;
        var localIpV6Exists = false;

        // these variables will hold the failing rules description
        var ipDescription;
        var ipv6Description;
        var ipv4InputKey = pluginName + 'ReplacementIpAddress';
        var ipv6InputKey = pluginName + 'ReplacementIpv6Address';

        if (failingPermission.IpRanges && failingPermission.IpRanges.length) {
            failingPermission.IpRanges.forEach(ipRange => {
                if (ipRange.CidrIp && ipRange.CidrIp === '0.0.0.0/0') {
                    openIpRange = true;
                    // Grabs the description when it identifies the failing rule
                    ipDescription = ipRange.Description ? ipRange.Description : null;
                } else if (ipRange.CidrIp && settings.input && settings.input[ipv4InputKey] && ipRange.CidrIp === settings.input[ipv4InputKey]) {
                    localIpExists = true;
                } else {
                    finalIpRanges.push(ipRange);
                }
            });
        }
        if (failingPermission.Ipv6Ranges && failingPermission.Ipv6Ranges.length) {
            failingPermission.Ipv6Ranges.forEach(ipv6Range => {
                if (ipv6Range.CidrIpv6 && ipv6Range.CidrIpv6 === '::/0') {
                    openIpv6Range = true;
                    // Grabs the description when it identifies the failing rule
                    ipv6Description = ipv6Range.Description ? ipv6Range.Description : null;
                } else if (ipv6Range.CidrIpv6 && settings.input && settings.input[ipv6InputKey] && ipv6Range.CidrIpv6 === settings.input[ipv6InputKey]) {
                    localIpV6Exists = true;
                } else {
                    finalIpv6Ranges.push(ipv6Range);
                }
            });
        }
        // changed to make this check right after getting both variables
        if (!openIpv6Range && !openIpRange) return fpCb();

        var params = {
            DryRun: false,
            GroupId: securityGroup.GroupId,
            IpPermissions: [
                {
                    IpRanges: failingPermission.IpRanges,
                    Ipv6Ranges: failingPermission.Ipv6Ranges,
                    PrefixListIds: failingPermission.PrefixListIds.length ? failingPermission.PrefixListIds : null,
                    UserIdGroupPairs: failingPermission.UserIdGroupPairs.length ? failingPermission.UserIdGroupPairs : null,
                    ToPort: failingPermission.ToPort,
                    FromPort: failingPermission.FromPort,
                    IpProtocol: failingPermission.IpProtocol,
                }
            ],
        };

        remediation_file['pre_remediate']['actions'][pluginName][resource].push(JSON.parse(JSON.stringify(params)));

        params.IpPermissions[0].Ipv6Ranges = [];
        params.IpPermissions[0].IpRanges = [];
        params.IpPermissions[0].UserIdGroupPairs = null;

        var oldIpv6Range = {CidrIpv6: '::/0'};
        var oldIpRange = {CidrIp: '0.0.0.0/0'};

        // this checks if a description was found then adds it to the new ip range


        async.series([
            function(rCb) {
                if (!settings.input || (openIpRange && (!settings.input[ipv4InputKey] || !settings.input[ipv4InputKey].length)) && (openIpv6Range && (!settings.input[ipv6InputKey] || !settings.input[ipv6InputKey].length))) return rCb();

                var newIpRange = settings.input[ipv4InputKey] ? {CidrIp: settings.input[ipv4InputKey]} : null;
                var newIpv6Range = settings.input[ipv6InputKey] ? {CidrIpv6: settings.input[ipv6InputKey]} : null;
                if (ipDescription && newIpRange) newIpRange.Description = ipDescription;
                if (ipv6Description && newIpv6Range) newIpRange.Description = ipv6Description;

                if (openIpRange && !localIpExists && settings.input[ipv4InputKey]) {
                    params.IpPermissions[0].IpRanges.push(newIpRange);
                    finalIpRanges.push(newIpRange);
                } else if (!openIpRange || (openIpRange && localIpExists) || (!settings.input[ipv4InputKey] || !settings.input[ipv4InputKey].length)) {
                    params.IpPermissions[0].IpRanges = null;
                }

                if (openIpv6Range && !localIpV6Exists && settings.input[ipv6InputKey]) {
                    params.IpPermissions[0].Ipv6Ranges.push(newIpv6Range);
                    finalIpv6Ranges.push(newIpv6Range);
                } else if (!openIpv6Range || (openIpv6Range && localIpV6Exists) || (!settings.input[ipv6InputKey] || !settings.input[ipv6InputKey].length)) {
                    params.IpPermissions[0].Ipv6Ranges = null;
                }

                remediatePlugin(config, putCall[0], params, function(err) {
                    if (err) {
                        errors.push(err);
                        return rCb(err);
                    } else {
                        if (openIpv6Range && !localIpV6Exists) {
                            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                                'inboundRule': '::1/128',
                                'action': 'ADDED'
                            });
                        } else if (openIpv6Range && localIpV6Exists) {
                            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                                'inboundRule': '::1/128',
                                'action': 'Already Exists'
                            });
                        }

                        if (openIpRange && !localIpExists) {
                            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                                'inboundRule': '127.0.0.1/32',
                                'action': 'ADDED'
                            });
                        } else if (openIpRange && localIpExists){
                            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                                'inboundRule': '127.0.0.1/32',
                                'action': 'Already Exists'
                            });
                        }

                        return rCb();
                    }
                });

            },
            function(rCb) {
                if (openIpRange) {
                    params.IpPermissions[0].IpRanges = [];
                    params.IpPermissions[0].IpRanges.push(oldIpRange);
                } else {
                    params.IpPermissions[0].IpRanges = null;
                }

                if (openIpv6Range) {
                    params.IpPermissions[0].Ipv6Ranges = [];
                    params.IpPermissions[0].Ipv6Ranges.push(oldIpv6Range);
                } else {
                    params.IpPermissions[0].Ipv6Ranges = null;
                }

                remediatePlugin(config, putCall[1], params, function(err) {
                    if (err) {
                        errors.push(err);
                        return rCb(err);
                    }
                    if (openIpRange) {
                        remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                            'inboundRule': '0.0.0.0/0',
                            'action': 'DELETED'
                        });
                        params.IpPermissions[0].IpRanges = finalIpRanges;
                    }
                    if (openIpv6Range) {
                        remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                            'inboundRule': '::/0',
                            'action': 'DELETED'
                        });
                        params.IpPermissions[0].Ipv6Ranges = finalIpv6Ranges;
                    }

                    params.IpPermissions[0].UserIdGroupPairs = failingPermission.UserIdGroupPairs.length ? failingPermission.UserIdGroupPairs : null;
                    actions.push(params);
                    return rCb();
                });
            }
        ], function(err) {
            if (err) {
                errors.push(err);
                return fpCb();
            } else {
                return fpCb();
            }
        });
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

function getDefaultKeyId(cache, region, defaultKeyDesc) {
    var source = {};

    var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);

    if (!listKeys || listKeys.err || !listKeys.data || !listKeys.data.length) {
        return false;
    }

    var defaultKey = listKeys.data.find(key => {
        var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, key.KeyId]);

        if (describeKey && describeKey.data && describeKey.data.KeyMetadata) {
            var keyToAdd = describeKey.data.KeyMetadata;

            if (keyToAdd.KeyManager && keyToAdd.KeyManager === 'AWS' && keyToAdd.Description &&
                keyToAdd.Description.indexOf(defaultKeyDesc) === 0 && keyToAdd.Enabled && keyToAdd.KeyState && keyToAdd.KeyState === 'Enabled') {
                return keyToAdd;
            }
        }
    });

    if (defaultKey) return defaultKey.KeyId;

    return false;
}

function getOrganizationAccounts(listAccounts, accountId) {
    let orgAccountIds = [];
    if (listAccounts.data && listAccounts.data.length){
        listAccounts.data.forEach(account => {
            if (account.Id && account.Id !== accountId) orgAccountIds.push(account.Id);
        });      
    }
    return orgAccountIds;
}

module.exports = {
    addResult: addResult,
    findOpenPorts: findOpenPorts,
    waitForCredentialReport: waitForCredentialReport,
    normalizePolicyDocument: normalizePolicyDocument,
    globalPrincipal: globalPrincipal,
    userGlobalAccess: userGlobalAccess,
    crossAccountPrincipal: crossAccountPrincipal,
    defaultRegion: defaultRegion,
    defaultPartition: defaultPartition,
    remediatePlugin: remediatePlugin,
    nullArray: nullArray,
    divideArray:divideArray,
    remediatePasswordPolicy:remediatePasswordPolicy,
    remediateOpenPorts: remediateOpenPorts,
    hasFederatedUserRole: hasFederatedUserRole,
    getEncryptionLevel: getEncryptionLevel,
    extractStatementPrincipals: extractStatementPrincipals,
    getDefaultKeyId: getDefaultKeyId,
    isValidCondition: isValidCondition,
    isEffectiveStatement: isEffectiveStatement,
    getDenyActionResourceMap: getDenyActionResourceMap,
    getDenyPermissionsMap: getDenyPermissionsMap,
    isEffectivePolicyStatement: isEffectivePolicyStatement,
    getS3BucketLocation: getS3BucketLocation,
    getOrganizationAccounts: getOrganizationAccounts
};
