var async = require('async');
var helpers = require('../../../helpers/aws');

// Iam roles are detached from instances during the termination process
// So if the instance is in that temporary state (before it disappears),
// We don't want it to be reported as failing.
const statesWhichLoseIamRole = new Set(['shutting-down', 'terminated']);

module.exports = {
    title: 'Instance IAM Role',
    category: 'EC2',
    description: 'Ensures EC2 instances are using an IAM role instead of hard-coded AWS credentials',
    more_info: 'IAM roles should be assigned to all instances to enable them to access AWS resources. Using an IAM role is more secure than hard-coding AWS access keys into application code.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html',
    recommended_action: 'Attach an IAM role to the EC2 instance',
    apis: ['EC2:describeInstances'],
    settings: {
        instance_iam_role_threshold: {
            name: 'Instance IAM Role Threshold',
            description: 'If more than this number of instances are missing an IAM role, results will be collapsed into a single result to avoid excessive result counts. Max is 299.',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 10
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            instance_iam_role_threshold: settings.instance_iam_role_threshold || this.settings.instance_iam_role_threshold.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No instances found', region);
                return rcb();
            }

            var found = 0;

            for (var i in describeInstances.data) {
                var accountId = describeInstances.data[i].OwnerId;

                for (var j in describeInstances.data[i].Instances) {
                    var instance = describeInstances.data[i].Instances[j];
                    var instanceState = instance.State && instance.State.Name;
                    var instanceIamProfileArn = instance.IamInstanceProfile && instance.IamInstanceProfile.Arn;

                    if (!statesWhichLoseIamRole.has(instanceState) && !instanceIamProfileArn) {
                        found += 1;
                        helpers.addResult(results, 2,
                            'Instance does not use an IAM role', region,
                            'arn:aws:ec2:' + region + ':' + accountId + ':instance/' +
                            instance.InstanceId, custom);
                    }
                }
            }

            // Too many results to print individually
            if (found > config.instance_iam_role_threshold) {
                results = [];

                helpers.addResult(results, 2,
                    'Over ' + config.instance_iam_role_threshold + ' EC2 instances do not use an IAM role', region, null, custom);
            }

            if (!found) {
                helpers.addResult(results, 0,
                    'All ' + describeInstances.data.length + ' instances are using IAM roles', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
