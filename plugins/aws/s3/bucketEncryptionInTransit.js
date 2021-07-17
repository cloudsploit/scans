var helpers = require('../../../helpers/aws');

function statementDeniesInsecureTransport(statement, bucketResource) {
    if (!statement) return false;
    return (statement.Effect === 'Deny') &&
        (statement.Principal === '*') &&
        (Array.isArray(statement.Action)
            ? statement.Action.find(action => action === '*' || action === 's3:*')
            : (statement.Action === '*' || statement.Action === 's3:*')) &&
        Array.isArray(statement.Resource) &&
        statement.Resource.find(resource => resource === `${bucketResource}/*`) &&
        statement.Resource.find(resource => resource === bucketResource) &&
        (
            statement.Condition &&
            statement.Condition.Bool &&
            statement.Condition.Bool['aws:SecureTransport'] &&
            statement.Condition.Bool['aws:SecureTransport'] === 'false'
        );
}

module.exports = {
    title: 'S3 Bucket Encryption In Transit',
    category: 'S3',
    description: 'Ensures S3 buckets have bucket policy statements that deny insecure transport',
    more_info: 'S3 bucket policies can be configured to deny access to the bucket over HTTP.',
    recommended_action: 'Add statements to the bucket policy that deny all S3 actions when SecureTransport is false. Resources must be list of bucket ARN and bucket ARN with wildcard.',
    link: 'https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy', 'S3:getBucketLocation'],
    remediation_description: 'The policy that deny all S3 actions when SecureTransport is false will be added in the impacted buckets.',
    remediation_min_version: '202006020730',
    apis_remediate: ['S3:listBuckets', 'S3:getBucketPolicy'],
    actions: {
        remediate: ['S3:putBucketPolicy'],
        rollback: ['S3:putBucketPolicy']
    },
    permissions: {
        remediate: ['s3:PutBucketPolicy'],
        rollback: ['s3:PutBucketPolicy ']
    },
    realtime_triggers: ['s3:putBucketPolicy', 's3:CreateBucket'],
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);
        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, `Unable to query for S3 buckets: ${helpers.addError(listBuckets)}`);
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }

        for (let bucket of listBuckets.data) {
            var bucketResource = `arn:aws:s3:::${bucket.Name}`;
            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);

            var getBucketPolicy = helpers.addSource(cache, source, ['s3', 'getBucketPolicy', region, bucket.Name]);
            if (getBucketPolicy && getBucketPolicy.err && getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 2, 'No bucket policy found; encryption in transit not enforced', bucketLocation, bucketResource);
                continue;
            }
            if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3, `Error querying for bucket policy on bucket: ${bucket.Name}: ${helpers.addError(getBucketPolicy)}`, bucketLocation, bucketResource);
                continue;
            }
            try {
                // Parse the policy if it hasn't be parsed and replaced by another plugin....
                var policyJson;
                if (typeof getBucketPolicy.data.Policy === 'string') {
                    policyJson = JSON.parse(getBucketPolicy.data.Policy);
                } else {
                    policyJson = getBucketPolicy.data.Policy;
                }
            } catch (e) {
                helpers.addResult(results, 3, `Bucket policy on bucket ${bucket.Name} could not be parsed.`, bucketLocation, bucketResource);
                continue;
            }
            if (!policyJson || !policyJson.Statement) {
                helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON is invalid or does not contain valid statements.`, bucketLocation, bucketResource);
                continue;
            }
            if (!policyJson.Statement.length) {
                helpers.addResult(results, 2, 'Bucket policy does not contain any statements; encryption in transit not enforced', bucketLocation, bucketResource);
                continue;
            }

            if (policyJson.Statement.find(statement => statementDeniesInsecureTransport(statement, bucketResource))) {
                helpers.addResult(results, 0, 'Bucket policy enforces encryption in transit', bucketLocation, bucketResource);
            } else {
                helpers.addResult(results, 2, 'Bucket does not enforce encryption in transit', bucketLocation, bucketResource);
            }
        }
        callback(null, results, source);
    },
    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'bucketEncryptionInTransit';
        var bucketNameArr = resource.split(':');
        var bucketName = bucketNameArr[bucketNameArr.length - 1];

        // find the location of the bucket needing to be remediated
        var bucketPolicies = cache['s3']['getBucketPolicy'];
        var bucketLocation;
        var err;
        if ( !bucketPolicies || bucketPolicies.err || Object.keys(bucketPolicies).length){
            err = bucketLocation.err || 'Unable to get bucket location';
            return callback(err, null);
        }

        for (var key in bucketPolicies) {
            if (bucketPolicies[key][bucketName]) {
                bucketLocation = key;
                break;
            }
        }
        var policy = bucketPolicies[key][bucketName];
        // add the location of the bucket to the config
        if (!bucketLocation) {
            err = 'Unable to get bucket location';
            return callback(err, null);
        }

        // create the params necessary for the remediation
        var params = {};
        var SecureTransport = {
            'Sid':'DenyInSecureTransport',
            'Effect': 'Deny',
            'Principal': '*',
            'Action': 's3:*',
            'Resource': [resource,resource+'/*'],
            'Condition': {
                'Bool': {
                    'aws:SecureTransport': 'false'
                }
            }
        };
        var policyBody = {
            'Version': '2012-10-17'
        };
        if (policy.err && policy.err.code &&
            policy.err.code === 'NoSuchBucketPolicy'){
            policyBody['Statement'] = SecureTransport;
            params = {
                'Bucket': bucketName,
                'Policy': JSON.stringify(policyBody)
            };
        } else {
            if (policy.data && policy.data.Policy){
                var policyJson;
                if (typeof policy.data.Policy === 'string') {
                    policyJson = JSON.parse(policy.data.Policy);
                } else {
                    policyJson = policy.data.Policy;
                }
                policyJson.Statement.push(SecureTransport);
                params = {
                    'Bucket': bucketName,
                    'Policy': JSON.stringify(policyJson)
                };
            }
        }
        var remediation_file = settings.remediation_file;

        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'VersioningConfiguration': 'Suspended',
            'Bucket': bucketName
        };

        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'VersioningConfiguration': 'Enabled',
                'Bucket': bucketName
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    },
    rollback: function(config, cache, settings, resource, callback){
        console.log('Rollback support for this plugin has not yet been implemented');
        console.log(config, cache, settings, resource);
        callback();
    }
};
