var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Versioning',
    category: 'S3',
    description: 'Ensures object versioning is enabled on S3 buckets',
    more_info: 'Object versioning can help protect against the overwriting of \
                objects or data loss in the event of a compromise.',
    recommended_action: 'Enable object versioning for buckets with \
                        sensitive contents at a minimum and for all buckets \
                        ideally.',
    link: 'http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html',
    apis: ['S3:listBuckets', 'S3:getBucketVersioning', 'S3:getBucketLocation'],
    remediation_description: 'The impacted bucket will be configured to be have Versioning enabled.',
    remediation_min_version: '202010211553',
    apis_remediate: ['S3:listBuckets', 'S3:getBucketVersioning', 'S3:getBucketLocation'],
    actions: {
        remediate: ['S3:putBucketVersioning'],
        rollback: ['S3:putBucketVersioning'],
    },
    permissions: {
        remediate: ['s3:PutBucketVersioning'],
        rollback: ['s3:PutBucketVersioning']
    },
    realtime_triggers: ['s3:CreateBucket', 's3:PutBucketVersioning'],
    asl: {
        conditions: [
            {
                service: 's3',
                api: 'getBucketVersioning',
                property: 'Status',
                transform: 'STRING',
                op: 'EXISTS',
            },
            {
                service: 's3',
                api: 'getBucketVersioning',
                property: 'Status',
                transform: 'STRING',
                op: 'EQ',
                value: 'Enabled',
                logical: 'AND'
            },
            {
                service: 's3',
                api: 'getBucketVersioning',
                property: 'Status',
                transform: 'STRING',
                op: 'MATCHES',
                value: '^[A-Z]{1}[a-z]+$',
                logical: 'AND'
            }
        ]

    },
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }

        listBuckets.data.forEach(function(bucket){
            var getBucketVersioning = helpers.addSource(cache, source,
                ['s3', 'getBucketVersioning', region, bucket.Name]);

            if (!getBucketVersioning || getBucketVersioning.err || !getBucketVersioning.data) {
                helpers.addResult(results, 3,
                    'Error querying bucket versioning for : ' + bucket.Name +
                    ': ' + helpers.addError(getBucketVersioning),
                    'global', 'arn:aws:s3:::' + bucket.Name);
            } else if (getBucketVersioning.data.Status == 'Enabled') {
                helpers.addResult(results, 0,
                    'Bucket : ' + bucket.Name + ' has versioning enabled',
                    'global', 'arn:aws:s3:::' + bucket.Name);
            } else {
                helpers.addResult(results, 2,
                    'Bucket : ' + bucket.Name + ' has versioning disabled',
                    'global', 'arn:aws:s3:::' + bucket.Name);
            }
        });

        callback(null, results, source);
    },

    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'bucketVersioning';
        var bucketNameArr = resource.split(':');
        var bucketName = bucketNameArr[bucketNameArr.length - 1];

        // find the location of the bucket needing to be remediated
        var bucketLocations = cache['s3']['getBucketLocation'];
        var bucketLocation;
        var err;

        if (!bucketLocations || bucketLocations.err || !Object.keys(bucketLocations).length){
            err =  bucketLocations.err || 'Unable to get bucket location';
            return callback(err, null);
        }

        for (var key in bucketLocations) {
            if (bucketLocations[key][bucketName]) {
                bucketLocation = key;
                break;
            }
        }
        if (!bucketLocation) {
            err = 'Unable to get bucket location';
            return callback(err, null);
        }

        // add the location of the bucket to the config
        config.region = bucketLocation;
        var params = {};
        // create the params necessary for the remediation
        params = {
            'Bucket': bucketName,
            'VersioningConfiguration': {
                Status: 'Enabled'
            }
        };
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

    rollback: function(config, cache, settings, resource, callback) {
        console.log('Rollback support for this plugin has not yet been implemented');
        console.log(config, cache, settings, resource);
        callback();
    }
};