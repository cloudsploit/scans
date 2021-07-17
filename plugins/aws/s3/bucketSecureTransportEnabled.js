var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Secure Transport Enabled',
    category: 'S3',
    description: 'Ensure AWS S3 buckets enforce SSL to secure data in transit',
    more_info: 'S3 buckets should be configured to strictly require SSL connections ' +
               'to deny unencrypted HTTP requests when dealing with sensitive data.',
    recommended_action: 'Update S3 bucket policy to enforse SSL to secure data in transit.',
    link: 'https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy', 'S3:getBucketLocation'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                `Unable to query for S3 buckets: ${helpers.addError(listBuckets)}`);
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets found');
            return callback(null, results, source);
        }

        listBuckets.data.forEach(bucket => {
            if (!bucket.Name) return;

            var resource = 'arn:aws:s3:::' + bucket.Name;
            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);

            var getBucketPolicy = helpers.addSource(cache, source,
                ['s3', 'getBucketPolicy', region, bucket.Name]);

            // Check the bucket policy
            if (getBucketPolicy && getBucketPolicy.err &&
                getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 2, 'No bucket policy found', bucketLocation, resource);
            } else if (!getBucketPolicy || getBucketPolicy.err ||
                       !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3,
                    `Error querying for bucket policy for bucket "${bucket.Name}" ${helpers.addError(getBucketPolicy)}`,
                    bucketLocation, resource);
            } else {
                var statements = helpers.normalizePolicyDocument(getBucketPolicy.data.Policy);

                if (!statements || !statements.length) {
                    helpers.addResult(results, 2,
                        'Bucket policy does not contain any statements',
                        bucketLocation, resource);
                    return;
                }

                var denyPermissionsMap = helpers.getDenyPermissionsMap(statements);
                var sslEnforced = true;
                for (var statement of statements) {
                    if (statement.Effect && statement.Effect === 'Allow' && statement.Principal && !statement.Principal.Service) {
                        if (!helpers.isEffectiveStatement(statement, denyPermissionsMap)) continue;
                        if (!statement.Condition ||
                                !statement.Condition.Bool ||
                                !statement.Condition.Bool['aws:SecureTransport'] ||
                                statement.Condition.Bool['aws:SecureTransport'] === 'false') {
                            sslEnforced = false;
                            break;
                        }
                    } else if (statement.Effect && statement.Effect === 'Deny' && statement.Principal && !statement.Principal.Service && statement.Sid) {
                        var denyActionResourceMap = helpers.getDenyPermissionsMap(statements, statement.Sid);
                        if (!helpers.isEffectiveStatement(statement, denyActionResourceMap)) continue;
                        if (!statement.Condition ||
                                !statement.Condition.Bool ||
                                !statement.Condition.Bool['aws:SecureTransport'] ||
                                statement.Condition.Bool['aws:SecureTransport'] === 'true') {
                            sslEnforced = false;
                            break;
                        }
                    }
                }

                if (sslEnforced) {
                    helpers.addResult(results, 0,
                        `Bucket Policy for bucket "${bucket.Name}" enforces SSL to secure data in transit`,
                        bucketLocation, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Bucket Policy for bucket "${bucket.Name}" does not enforce SSL to secure data in transit`,
                        bucketLocation, resource);
                }
            }
        });

        callback(null, results, source);
    }
};