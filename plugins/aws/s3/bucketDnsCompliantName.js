var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 DNS Compliant Bucket Names',
    category: 'S3',
    description: 'Ensures that S3 buckets have DNS complaint bucket names.',
    more_info: 'S3 bucket names must be DNS-compliant and not contain period "." to enable S3 Transfer Acceleration and to use buckets over SSL.',
    recommended_action: 'Recreate S3 bucket to use "-" instead of "." in S3 bucket names.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html',
    apis: ['S3:listBuckets', 'S3:getBucketLocation'],

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

        for (var bucket of listBuckets.data) {
            var resource = `arn:aws:s3:::${bucket.Name}`;
            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);
            if (bucket.Name && bucket.Name.indexOf('.') === -1) {
                helpers.addResult(results, 0,
                    'S3 bucket name is compliant with DNS naming requirements',
                    bucketLocation, resource);
            } else {
                helpers.addResult(results, 2,
                    'S3 bucket name is not compliant with DNS naming requirements',
                    bucketLocation, resource);
            }
        }

        callback(null, results, source);
    },
};