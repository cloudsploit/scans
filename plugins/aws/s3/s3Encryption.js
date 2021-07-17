var minimatch = require('minimatch');
var helpers = require('../../../helpers/aws');

const encryptionLevelMap = {
    none: 0,
    sse: 1, // // x-amz-server-side-encryption:AES256
    awskms: 2, // x-amz-server-side-encryption:aws:kms without x-amz-server-side-encryption-aws-kms-key-id, implies any KMS key
    awscmk: 3, // x-amz-server-side-encryption:aws:kms with x-amz-server-side-encryption-aws-kms-key-id, but key is customer managed
    externalcmk: 4, // x-amz-server-side-encryption:aws:kms with x-amz-server-side-encryption-aws-kms-key-id, but key is externalcmk
    cloudhsm: 5, // x-amz-server-side-encryption:aws:kms with x-amz-server-side-encryption-aws-kms-key-id, but key is cloudhsm
};

function statementTargetsAction(statement, targetAction) {
    return Array.isArray(statement.Action)
        ? statement.Action.find(action => minimatch(targetAction, action))
        : minimatch(targetAction, statement.Action);
}

/**
 * Return the encryption level for the statement
 * If multiple conditions in StringNotEquals, return the least-restrictive condition found first (sse)
 */
function getEncryptionLevel(statement) {
    if (statement) {
        if (statement.Effect === 'Deny' && statement.Principal === '*') {
            if (statementTargetsAction(statement, 's3:PutObject')) {
                if (statement.Condition && statement.Condition.StringNotEquals) {
                    if (statement.Condition.StringNotEquals['s3:x-amz-server-side-encryption'] === 'AES256') {
                        return { level: 'sse' };
                    }
                    if (statement.Condition.StringNotEquals['s3:x-amz-server-side-encryption'] === 'aws:kms') {
                        return { level: 'awskms' };
                    }
                    if (statement.Condition.StringNotEquals['s3:x-amz-server-side-encryption-aws-kms-key-id']) {
                        return { key: statement.Condition.StringNotEquals['s3:x-amz-server-side-encryption-aws-kms-key-id'] };
                    }
                }
            }
        }
    }
    return { level: 'off' }; // no encryption requirements on all s3:PutObject calls from everyone
}

function getKeyEncryptionLevel(kmsKey) {
    return kmsKey.Origin === 'AWS_CLOUDHSM' ? 'cloudhsm' :
        kmsKey.Origin === 'EXTERNAL' ? 'externalcmk' :
            kmsKey.KeyManager === 'CUSTOMER' ? 'awscmk' : 'awskms';
}

module.exports = {
    title: 'S3 Bucket Encryption Enforcement',
    category: 'S3',
    description: 'All statements in all S3 bucket policies must have a condition that requires encryption at a certain level',
    more_info: 'S3 buckets support numerous types of encryption, including AES-256, KMS using a default key, KMS with a CMK, or via HSM-based key.',
    recommended_action: 'Configure a bucket policy to enforce encryption.',
    link: 'https://aws.amazon.com/blogs/security/how-to-prevent-uploads-of-unencrypted-objects-to-amazon-s3/',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy', 'S3:getBucketLocation', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        s3_required_encryption_level: {
            name: 'S3 Minimum Default Encryption Level',
            description: 'In order (low to high) sse=Server-Side Encryption; awskms=AWS KMS; awscmk=Customer KMS; externalcmk=Customer external KMS; cloudhsm=Customer CloudHSM',
            regex: '^(sse|awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'sse',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var desiredEncryptionLevelString = settings.s3_required_encryption_level || this.settings.s3_required_encryption_level.default;
        if (!desiredEncryptionLevelString.match(this.settings.s3_required_encryption_level.regex)) {
            helpers.addResult(results, 3, 'Settings misconfigured for S3 Encryption Enforcement.');
            return callback(null, results, source);
        }

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
                helpers.addResult(results, 2, 'No bucket policy found; encryption not enforced', bucketLocation, bucketResource);
                continue;
            }
            if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3, `Error querying for bucket policy on bucket: ${bucket.Name}: ${helpers.addError(getBucketPolicy)}`, bucketLocation, bucketResource);
                continue;
            }

            try {
                // Parse the policy if it hasn't been parsed and replaced by another plugin....
                var policyJson;
                if (typeof getBucketPolicy.data.Policy === 'string') {
                    policyJson = JSON.parse(getBucketPolicy.data.Policy);
                } else {
                    policyJson = getBucketPolicy.data.Policy;
                }
            } catch (e) {
                helpers.addResult(results, 3, `Bucket policy on bucket [${bucket.Name}] could not be parsed.`, bucketLocation, bucketResource);
                continue;
            }
            if (!policyJson || !policyJson.Statement) {
                helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON is invalid or does not contain valid statements.`, bucketLocation, bucketResource);
                continue;
            }
            if (!policyJson.Statement.length) {
                helpers.addResult(results, 2, 'Bucket policy does not contain any statements; encryption not enforced', bucketLocation, bucketResource);
                continue;
            }

            var statementEncryptionLevels = policyJson.Statement.map(statement => {
                const encryptionLevel = getEncryptionLevel(statement);
                if (encryptionLevel.level) return encryptionLevel.level;
                if (encryptionLevel.key) {
                    const keyId = encryptionLevel.key.split('/')[1];
                    const describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);
                    if (!describeKey || describeKey.err || !describeKey.data) {
                        helpers.addResult(results, 3, `Unable to query for KMS Key: ${helpers.addError(describeKey)}`, region, keyId);
                        return 0;
                    }
                    return getKeyEncryptionLevel(describeKey.data.KeyMetadata);
                }
                return 0;
            });

            // get max encryption level string
            const currentEncryptionLevel = statementEncryptionLevels.reduce((max, level) => encryptionLevelMap[level] > encryptionLevelMap[max] ? level : max, 'none');

            if (encryptionLevelMap[currentEncryptionLevel] < encryptionLevelMap[desiredEncryptionLevelString]) {
                helpers.addResult(results, 2, `Bucket policy does not enforce encryption to ${desiredEncryptionLevelString}, policy currently enforces: ${currentEncryptionLevel}`, bucketLocation, bucketResource);
            } else {
                helpers.addResult(results, 0, `Bucket policy enforces encryption to ${desiredEncryptionLevelString}, policy currently enforces: ${currentEncryptionLevel}`, bucketLocation, bucketResource);
            }
        }
        callback(null, results, source);
    }
};
