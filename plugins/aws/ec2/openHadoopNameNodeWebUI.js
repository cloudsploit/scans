var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open Hadoop HDFS NameNode WebUI',
    category: 'EC2',
    description: 'Determine if TCP port 50070 and 50470 for Hadoop/HDFS NameNode WebUI service is open to the public',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Hadoop/HDFS should be restricted to known IP addresses.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Restrict TCP port 50070 and 50470 to known IP addresses for Hadoop/HDFS',
    apis: ['EC2:describeSecurityGroups'],
    remediation_description: 'The impacted security group rule will be deleted if no input is provided. Otherwise, any input will replace the open CIDR rule.',
    remediation_min_version: '202006020730',
    apis_remediate: ['EC2:describeSecurityGroups'],
    remediation_inputs: {
        openHadoopNameNodeWebUIReplacementIpAddress: {
            name: '(Optional) Replacement IPv4 CIDR',
            description: 'The IPv4 CIDR block used to replace the open IP rule',
            regex: '^([0-9]{1,3}\\.){3}[0-9]{1,3}(\\/([0-9]|[1-2][0-9]|3[0-2]))$',
            required: false
        },
        openHadoopNameNodeWebUIReplacementIpv6Address: {
            name: '(Optional) Replacement IPv6 CIDR',
            description: 'The IPv6 CIDR block used to replace the open IP rule',
            regex: '^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))$',
            required: false
        }
    },
    actions: {
        remediate: ['EC2:authorizeSecurityGroupIngress','EC2:revokeSecurityGroupIngress'],
        rollback: ['EC2:authorizeSecurityGroupIngress']
    },
    permissions: {
        remediate: ['ec2:AuthorizeSecurityGroupIngress','ec2:RevokeSecurityGroupIngress'],
        rollback:['ec2:AuthorizeSecurityGroupIngress']
    },
    realtime_triggers: ['ec2:AuthorizeSecurityGroupIngress'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var ports = {
            'tcp': [50070,50470]
        };

        var service = 'NameNodeWebUI';

        async.each(regions.ec2, function(region, rcb){
            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups present', region);
                return rcb();
            }

            helpers.findOpenPorts(describeSecurityGroups.data, ports, service, region, results);

            rcb();
        }, function(){
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;
        var pluginName = 'openHadoopNameNodeWebUI';
        var protocol = 'tcp';
        var ports = [50070, 50470];
        var actions = [];
        var errors = [];

        async.each(ports,function(port, cb) {
            helpers.remediateOpenPorts(putCall, pluginName, protocol, port, config, cache, settings, resource, remediation_file, function(error, action) {
                if (error && error.length) {
                    errors.push(error);
                } else if (action && (action.length || Object.keys(action).length)){
                    actions.push(action);
                }

                cb();
            });
        }, function() {
            if (errors && errors.length) {
                remediation_file['post_remediate']['actions'][pluginName]['error'] = errors.join(', ');
                settings.remediation_file = remediation_file;
                return callback(errors, null);
            } else {
                remediation_file['post_remediate']['actions'][pluginName][resource] = actions;
                settings.remediation_file = remediation_file;
                return callback(null, actions);
            }
        });
    }
};
