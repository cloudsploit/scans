var helpers = require('../shared.js');

function defaultRegion(settings) {
    if (settings.defaultRegion) return settings.defaultRegion;
    return 'cn-hangzhou';
}

function createArn(service, account, resourceType, resourceId, region) {
    if (!region) region = '';
    return `arn:acs:${service}:${region}:${account}:${resourceType}/${resourceId}`;
}

function findOpenPorts(cache, groups, ports, service, region, results) {
    var found = false;

    for (var group of groups) {
        if (!group.SecurityGroupId) continue;

        var accountId = helpers.addSource(cache, {}, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);

        var resource = createArn('ecs', accountId, 'securitygroup', group.SecurityGroupId, region);

        var describeSecurityGroupAttribute = helpers.addSource(cache, {},
            ['ecs', 'DescribeSecurityGroupAttribute', region, group.SecurityGroupId]);

        if (!describeSecurityGroupAttribute || describeSecurityGroupAttribute.err || !describeSecurityGroupAttribute.data) {
            helpers.addResult(results, 3,
                `Unable to query security group attributes: ${describeSecurityGroupAttribute}`, region, resource);
            continue;
        }

        var string;
        var openV4Ports = [];

        if (describeSecurityGroupAttribute.data.Permissions && describeSecurityGroupAttribute.data.Permissions.Permission && describeSecurityGroupAttribute.data.Permissions.Permission.length){
            for (var permission of describeSecurityGroupAttribute.data.Permissions.Permission) {
                if (permission.Direction && permission.Direction !== 'ingress') continue;
                let protocol = permission.IpProtocol.toLowerCase();
                if (permission.SourceCidrIp === '0.0.0.0/0' && ports[protocol]) {
                    for (var port of ports[protocol]) {
                        let fromPort = (Number(permission.PortRange.split('/')[0])) ?
                            Number(permission.PortRange.split('/')[0]) : Number(permission.PortRange);
                        let toPort = (Number(permission.PortRange.split('/')[1])) ?
                            Number(permission.PortRange.split('/')[1]) : Number(permission.PortRange);

                        if (port.toString().indexOf('-') > -1) {
                            var rangeFrom = Number(port.split('-')[0]);
                            var rangeTo = Number(port.split('-')[1]);

                            for (let i = rangeFrom; i <= rangeTo; i++) {
                                if (fromPort<= i && toPort >= i) {
                                    string = `some of ${permission.IpProtocol}:${port}`;
                                    if (openV4Ports.indexOf(string) === -1) openV4Ports.push(string);
                                    found = true;
                                    break;
                                }
                            }
                        } else {
                            port = Number(port);
                            if (fromPort <= port && toPort >= port) {
                                string = `${permission.IpProtocol}:${port}`;
                                if (openV4Ports.indexOf(string) === -1) openV4Ports.push(string);
                                found = true;
                            }
                        }
                    }
                }
            }
        }

        if (openV4Ports.length) {
            var resultsString = '';
            if (openV4Ports.length) {
                resultsString = `Security group: ${group.SecurityGroupId} has ${service}:${openV4Ports.join(', ')} open to 0.0.0.0/0`;
            }

            helpers.addResult(results, 2, resultsString, region, resource);
        }
    }

    if (!found) {
        helpers.addResult(results, 0, 'No public open ports found', region);
    }

    return;
}

function getEncryptionLevel(kmsKey, encryptionLevels) {
    if (kmsKey.Origin) {
        if (kmsKey.Origin === 'Aliyun_KMS') {
            if (kmsKey.ProtectionLevel) {
                if (kmsKey.ProtectionLevel.toUpperCase() == 'SOFTWARE') return encryptionLevels.indexOf('alibabacmk');
                if (kmsKey.ProtectionLevel.toUpperCase() == 'HSM') return encryptionLevels.indexOf('cloudhsm');
            }
        }
        if (kmsKey.Origin === 'EXTERNAL') return encryptionLevels.indexOf('externalcmk');
    }

    return encryptionLevels.indexOf('none');
}

module.exports = {
    defaultRegion: defaultRegion,
    createArn: createArn,
    findOpenPorts: findOpenPorts,
    getEncryptionLevel: getEncryptionLevel
};