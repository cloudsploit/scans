var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Bucket CMK Encrypted',
    category: 'OSS',
    description: 'Ensure that OSS buckets are encrypted using Alibaba CMK.',
    more_info: 'OSS buckets should be encrypted using customer master keys in order to gain greater control and transparency, ' +
        'as well as increasing security by having full control of the encryption keys.',
    recommended_action: 'Modify bucket\'s server-side encrypted setting to configure encryption method as KMS',
    link: 'https://www.alibabacloud.com/help/doc-detail/31871.html',
    apis: ['OSS:listBuckets', 'OSS:getBucketInfo', 'KMS:ListKeys', 'KMS:DescribeKey', 'STS:GetCallerIdentity'],
    settings: {
        oss_buckets_encryption_level: {
            name: 'OSS Buckets Encryption Level',
            description: 'In order (lowest to highest) ossmanaged=OSS-Managed; cloudkms=Alibaba managed default service KMS; alibabacmk=Customer managed KMS; externalcmk=Customer imported key; cloudhsm=Customer managed CloudHSM sourced Key',
            regex: '^(ossmanaged|cloudkms|alibabacmk|externalcmk|cloudhsm)$',
            default: 'alibabacmk',
        }
    },
    compliance: {
        hipaa: 'All data in HIPAA environments must be encrypted, including ' +
                'data at rest. OSS encryption ensures that this HIPAA control ' +
                'is implemented by providing KMS-backed encryption for all OSS ' +
                'buckets data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. OSS ' +
             'encryption should be enabled for all buckets storing this type ' +
             'of data.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', region, 'data']);

        var targetEncryptionLevelStr = settings.oss_buckets_encryption_level || this.settings.oss_buckets_encryption_level.default;
        var targetEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(targetEncryptionLevelStr);
        var currentEncryptionLevelStr;
        var currentEncryptionLevel;

        var listBuckets = helpers.addSource(cache, source, ['oss', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, `Unable to query for OSS buckets: ${helpers.addError(listBuckets)}`, region);
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No OSS buckets found', region);
            return callback(null, results, source);
        }

        var listKeys = helpers.addSource(cache, source, ['kms', 'ListKeys', region]);

        if (!listKeys || listKeys.err || !listKeys.data) {
            helpers.addResult(results, 3, 'Unable to query KMS keys: ' + helpers.addError(listKeys), region);
            return callback(null, results, source);
        }

        async.each(listBuckets.data, (bucket, cb) => {
            if (!bucket.name) return cb();

            var bucketLocation = bucket.region || region;
            bucketLocation = bucketLocation.replace('oss-', '');

            var getBucketInfo = helpers.addSource(cache, source,
                ['oss', 'getBucketInfo', region, bucket.name]);
    
            if (!getBucketInfo || getBucketInfo.err || !getBucketInfo.data) {
                helpers.addResult(results, 3,
                    `Unable to query OSS bucket info: ${helpers.addError(getBucketInfo)}`, bucketLocation, resource);
                return cb();
            }

            var resource = helpers.createArn('oss', accountId, 'bucket', bucket.name, bucketLocation);

            if (getBucketInfo.data.ServerSideEncryptionRule &&
                getBucketInfo.data.ServerSideEncryptionRule.SSEAlgorithm) {
                let sseRule = getBucketInfo.data.ServerSideEncryptionRule;
                let sseAlgo = getBucketInfo.data.ServerSideEncryptionRule.SSEAlgorithm;

                if (sseAlgo.toUpperCase() == 'NONE') {
                    helpers.addResult(results, 2,
                        'OSS bucket is not server-side encrypted', bucketLocation, resource);
                    return cb();
                }

                if (sseAlgo.toUpperCase() == 'KMS') {
                    if (sseRule.KMSMasterKeyID &&
                        sseRule.KMSMasterKeyID.length) {
                        let kmsKey = sseRule.KMSMasterKeyID;

                        var describeKey = helpers.addSource(cache, source, ['kms', 'DescribeKey', bucketLocation, kmsKey]);

                        if (!describeKey || describeKey.err || !describeKey.data) {
                            helpers.addResult(results, 3,
                                `Unable to query KMS key (${kmsKey}): ${helpers.addError(describeKey)}`,
                                bucketLocation, resource);
                            return cb();
                        }

                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data, helpers.ENCRYPTION_LEVELS);
                    } else {
                        currentEncryptionLevel = 2; // cloudkms
                    }
                } else {
                    currentEncryptionLevel = 1; // oss-managed
                }

                currentEncryptionLevelStr = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
                if (currentEncryptionLevel >= targetEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `OSS bucket is server-side encrypted to ${currentEncryptionLevelStr} which is greater than or equal to required level ${targetEncryptionLevelStr}`,
                        bucketLocation, resource);
                } else {
                    helpers.addResult(results, 2,
                        `OSS bucket is server-side encrypted to ${currentEncryptionLevelStr} which is less than required level ${targetEncryptionLevelStr}`,
                        bucketLocation, resource);
                }
            } else {
                helpers.addResult(results, 2,
                    'OSS bucket is not server-side encrypted', bucketLocation, resource);
            }

            cb();
        }, function() {
            callback(null, results, source);
        });
    }
};
