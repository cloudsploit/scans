var helpers = require('../../../helpers/aws');

var ACL_ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers';
var ACL_AUTHENTICATED_USERS = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers';

module.exports = {
    title: 'S3 Bucket All Users ACL',
    category: 'S3',
    description: 'Ensures S3 buckets do not allow global write, delete, or read ACL permissions',
    more_info: 'S3 buckets can be configured to allow anyone, regardless of whether they are an AWS user or not, to write objects to a bucket or delete objects. This option should not be configured unless there is a strong business requirement.',
    recommended_action: 'Disable global all users policies on all S3 buckets and ensure both the bucket ACL is configured with least privileges.',
    link: 'http://docs.aws.amazon.com/AmazonS3/latest/UG/EditingBucketPermissions.html',
    apis: ['S3:listBuckets', 'S3:getBucketAcl', 'S3:getBucketLocation'],
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. If PCI-restricted data is stored in S3, ' +
             'those buckets should not enable global user access.'
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

        for (var i in listBuckets.data) {
            var bucket = listBuckets.data[i];
            if (!bucket.Name) continue;

            var bucketResource = 'arn:aws:s3:::' + bucket.Name;
            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);

            var getBucketAcl = helpers.addSource(cache, source,
                ['s3', 'getBucketAcl', region, bucket.Name]);

            var bucketIssues = [];
            var bucketResult = 0;

            // Check the bucket ACL
            if (!getBucketAcl || getBucketAcl.err || !getBucketAcl.data) {
                helpers.addResult(results, 3,
                    'Error querying for bucket ACL for bucket: ' + bucket.Name +
                    ': ' + helpers.addError(getBucketAcl),
                    bucketLocation, bucketResource);
            } else {
                for (var g in getBucketAcl.data.Grants) {
                    var grant = getBucketAcl.data.Grants[g];

                    if (grant.Grantee &&
                        grant.Grantee.Type &&
                        grant.Grantee.Type === 'Group') {

                        var uri = grant.Grantee.URI;
                        var permission = grant.Permission;

                        if (uri === ACL_ALL_USERS) {
                            bucketIssues.push('ACL Grantee AllUsers allowed permission: ' + permission);
                            if (permission === 'READ') {
                                if (bucketResult < 1) bucketResult = 1;
                            } else {
                                if (bucketResult < 2) bucketResult = 2;
                            }
                        } else if (uri === ACL_AUTHENTICATED_USERS) {
                            bucketIssues.push('Grantee AuthenticatedUsers allowed permission: ' + permission);
                            if (permission === 'READ') {
                                if (bucketResult < 1) bucketResult = 1;
                            } else {
                                if (bucketResult < 2) bucketResult = 2;
                            }
                        }
                    }
                }

                if (!bucketIssues.length) {
                    helpers.addResult(results, 0,
                        'Bucket ACL does not contain any insecure allow statements',
                        bucketLocation, bucketResource);
                } else {
                    helpers.addResult(results, bucketResult,
                        bucketIssues.join(' '),
                        bucketLocation, bucketResource);
                }
            }
        }
        
        callback(null, results, source);
    }
};