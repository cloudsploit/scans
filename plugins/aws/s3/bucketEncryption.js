var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Encryption',
    category: 'S3',
    description: 'Ensures object encryption is enabled on S3 buckets',
    more_info: 'S3 object encryption provides fully-managed encryption of all objects uploaded to an S3 bucket.',
    recommended_action: 'Enable CMK KMS-based encryption for all S3 buckets.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html',
    apis: ['S3:listBuckets', 'S3:getBucketEncryption', 'S3:getBucketLocation', 'KMS:listKeys', 'KMS:describeKey', 'KMS:listAliases', 'CloudFront:listDistributions'],
    remediation_description: 'The impacted bucket will be configured to use either AES-256 encryption, or CMK-based encryption if a KMS key ID is provided.',
    remediation_min_version: '202006020730',
    apis_remediate: ['S3:listBuckets', 'S3:getBucketEncryption', 'S3:getBucketLocation'],
    actions: {
        remediate: ['S3:putBucketEncryption'],
        rollback: ['S3:deleteBucketEncryption']
    },
    permissions: {
        remediate: ['s3:PutEncryptionConfiguration'],
        rollback: ['s3:PutEncryptionConfiguration']
    },
    remediation_inputs: {
        kmsKeyId: {
            name: '(Optional) KMS Key ID',
            description: 'The KMS Key ID used for encryption',
            regex: '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$',
            required: false
        }
    },
    realtime_triggers: ['s3:DeleteBucketEncryption', 's3:CreateBucket'],
    settings: {
        s3_encryption_require_cmk: {
            name: 'S3 Encryption Require CMK',
            description: 'When set to true, S3 encryption using default KMS keys or AES will be marked as failing',
            regex: '^(true|false)$',
            default: 'false'
        },
        s3_encryption_allow_pattern: {
            name: 'S3 Encryption Allow Pattern',
            description: 'When set, whitelists buckets matching the given pattern. Useful for overriding buckets outside the account control.',
            regex: '^.{1,255}$',
            default: ''
        },
        s3_encryption_kms_alias: {
            name: 'S3 Encryption KMS Alias',
            description: 'If set, S3 encryption must be configured using the KMS key alias specified. Be sure to include the alias/ prefix. Comma-delimited.',
            regex: '^alias/[a-zA-Z0-9_/-,]{0,256}$',
            default: ''
        },
        s3_encryption_allow_cloudfront: {
            name: 'S3 Encryption Allow CloudFront',
            description: 'When set to true, buckets that serve as CloudFront origins will not be required to have CMK encryption (which is unsupported by CloudFront).',
            regex: '^(true|false)$',
            default: 'false'
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            s3_encryption_require_cmk: settings.s3_encryption_require_cmk || this.settings.s3_encryption_require_cmk.default,
            s3_encryption_allow_pattern: settings.s3_encryption_allow_pattern || this.settings.s3_encryption_allow_pattern.default,
            s3_encryption_kms_alias: settings.s3_encryption_kms_alias || this.settings.s3_encryption_kms_alias.default,
            s3_encryption_allow_cloudfront: settings.s3_encryption_allow_cloudfront || this.settings.s3_encryption_allow_cloudfront.default
        };

        config.s3_encryption_require_cmk = (config.s3_encryption_require_cmk == 'true');
        config.s3_encryption_allow_cloudfront = (config.s3_encryption_allow_cloudfront == 'true');

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var cloudfrontOrigins = [];
        var aliasKeyIds = [];
        var defaultKeyIds = [];
        var defaultKeyDesc = 'Default master key that protects my S3 objects';

        async.series([
            // Lookup the default master key for S3 if required
            function(cb) {
                if (!config.s3_encryption_require_cmk) return cb();
                async.each(regions.kms, function(region, rcb) {
                    // List the KMS Keys
                    var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);

                    if (!listKeys) return rcb();

                    if (listKeys.err || !listKeys.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for KMS: ' + helpers.addError(listKeys), region);
                        return rcb();
                    }

                    if (!listKeys.data.length) return rcb();

                    async.each(listKeys.data, function(key, kcb){
                        // Describe the KMS keys
                        var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, key.KeyId]);

                        if (describeKey && describeKey.data && describeKey.data.KeyMetadata) {
                            var keyToAdd = describeKey.data.KeyMetadata;

                            if (keyToAdd.KeyManager && keyToAdd.KeyManager == 'AWS' && keyToAdd.Description &&
                                keyToAdd.Description.indexOf(defaultKeyDesc) === 0) {
                                defaultKeyIds.push(keyToAdd.Arn);
                            }
                        }
                        
                        kcb();
                    }, function(){
                        rcb();
                    });
                }, function(){
                    cb();
                });
            },
            // Lookup the key aliases if required
            function(cb) {
                if (!config.s3_encryption_kms_alias) return cb();
                var configAliasIds = config.s3_encryption_kms_alias.split(',');

                async.each(regions.kms, function(region, rcb) {
                    var listAliases = helpers.addSource(cache, source,
                        ['kms', 'listAliases', region]);

                    var aliasIds = [];

                    if (!listAliases || listAliases.err ||
                        !listAliases.data) {
                        return rcb();
                    }

                    if (!listAliases.data.length) {
                        return rcb();
                    }

                    listAliases.data.forEach(function(alias){
                        if (configAliasIds.indexOf(alias.AliasName) > -1) {
                            aliasIds.push(alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId));
                        }
                    });

                    if (aliasIds.length) aliasKeyIds = aliasKeyIds.concat(aliasIds);

                    rcb();
                }, function(){
                    cb();
                });
            },
            // Find buckets serving as CloudFront origins
            function(cb){
                if (!config.s3_encryption_allow_cloudfront) return cb();
                var region = helpers.defaultRegion(settings);

                var listDistributions = helpers.addSource(cache, source,
                    ['cloudfront', 'listDistributions', region]);

                if (!listDistributions) return cb();

                if (listDistributions.err || !listDistributions.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions));
                    return cb();
                }

                listDistributions.data.forEach(function(distribution){
                    if (distribution.Origins &&
                        distribution.Origins.Items &&
                        distribution.Origins.Items.length) {
                        distribution.Origins.Items.forEach(function(item){
                            if (item.S3OriginConfig &&
                                item.DomainName && item.DomainName.indexOf('.s3.') > -1) {
                                // Below regex replaces the AWS-provided DNS for S3 buckets
                                cloudfrontOrigins.push(item.DomainName.replace(/\.s3\..*amazonaws\.com/g, ''));
                            }
                        });
                    }
                });

                cb();
            },
            // Check the S3 buckets for encryption
            function(cb) {
                var region = helpers.defaultRegion(settings);

                var listBuckets = helpers.addSource(cache, source,
                    ['s3', 'listBuckets', region]);

                if (!listBuckets) return cb();

                if (listBuckets.err || !listBuckets.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
                    return cb();
                }

                if (!listBuckets.data.length) {
                    helpers.addResult(results, 0, 'No S3 buckets to check');
                    return cb();
                }

                var allowRegex = (config.s3_encryption_allow_pattern &&
                    config.s3_encryption_allow_pattern.length) ? new RegExp(config.s3_encryption_allow_pattern) : false;

                listBuckets.data.forEach(function(bucket){
                    var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);

                    if (allowRegex && allowRegex.test(bucket.Name)) {
                        helpers.addResult(results, 0,
                            'Bucket: ' + bucket.Name + ' is whitelisted via custom setting.',
                            bucketLocation, 'arn:aws:s3:::' + bucket.Name, custom);
                    } else {
                        var getBucketEncryption = helpers.addSource(cache, source,
                            ['s3', 'getBucketEncryption', region, bucket.Name]);

                        if (getBucketEncryption && getBucketEncryption.err &&
                            getBucketEncryption.err.code && getBucketEncryption.err.code == 'ServerSideEncryptionConfigurationNotFoundError') {
                            helpers.addResult(results, 2,
                                'Bucket: ' + bucket.Name + ' has encryption disabled',
                                bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                        } else if (!getBucketEncryption || getBucketEncryption.err || !getBucketEncryption.data) {
                            helpers.addResult(results, 3,
                                'Error querying bucket encryption for: ' + bucket.Name +
                                ': ' + helpers.addError(getBucketEncryption),
                                bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                        } else if (getBucketEncryption.data.ServerSideEncryptionConfiguration &&
                                getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules &&
                                getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0] &&
                                getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault &&
                                getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm) {
                            var algo = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm;
                            var keyArn = getBucketEncryption.data.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID;

                            if (config.s3_encryption_require_cmk &&
                                (algo == 'AES256' || (algo == 'aws:kms' && defaultKeyIds.indexOf(keyArn) > -1))) {
                                if (config.s3_encryption_allow_cloudfront &&
                                    cloudfrontOrigins.indexOf(bucket.Name) > -1) {
                                    helpers.addResult(results, 0,
                                        'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled without a CMK but is a CloudFront origin',
                                        bucketLocation, 'arn:aws:s3:::' + bucket.Name, custom);
                                } else {
                                    helpers.addResult(results, 2,
                                        'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled but is not using a CMK',
                                        bucketLocation, 'arn:aws:s3:::' + bucket.Name, custom);
                                }
                            } else {
                                if (config.s3_encryption_kms_alias) {
                                    if (config.s3_encryption_allow_cloudfront &&
                                        cloudfrontOrigins.indexOf(bucket.Name) > -1) {
                                        helpers.addResult(results, 0,
                                            'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled but is a CloudFront origin',
                                            bucketLocation, 'arn:aws:s3:::' + bucket.Name, custom);
                                    } else if (!aliasKeyIds.length) {
                                        helpers.addResult(results, 2,
                                            'Bucket: ' + bucket.Name + ' has encryption enabled but matching KMS key alias ' + config.s3_encryption_kms_alias + ' could not be found in the account',
                                            bucketLocation, 'arn:aws:s3:::' + bucket.Name, custom);
                                    } else if (algo == 'aws:kms' && aliasKeyIds.indexOf(keyArn) > -1) {
                                        helpers.addResult(results, 0,
                                            'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled using required KMS key: ' + keyArn,
                                            bucketLocation, 'arn:aws:s3:::' + bucket.Name, custom);
                                    } else {
                                        var msg;
                                        if (algo !== 'aws:kms') {
                                            msg = 'Bucket: ' + bucket.Name + ' encryption (' + algo + ') is not configured to use required KMS key';
                                        } else {
                                            msg = 'Bucket: ' + bucket.Name + ' encryption (' + algo + ' with key: ' + keyArn + ') is not configured to use required KMS key';
                                        }

                                        helpers.addResult(results, 2, msg,bucketLocation, 'arn:aws:s3:::' + bucket.Name, custom);
                                    }
                                } else {
                                    helpers.addResult(results, 0,
                                        'Bucket: ' + bucket.Name + ' has ' + algo + ' encryption enabled',
                                        bucketLocation, 'arn:aws:s3:::' + bucket.Name, custom);
                                }
                            }
                        } else {
                            helpers.addResult(results, 2,
                                'Bucket: ' + bucket.Name + ' has encryption disabled',
                                bucketLocation, 'arn:aws:s3:::' + bucket.Name);
                        }
                    }
                });

                cb();
            }
        ], function(){
            callback(null, results, source);
        });
    },

    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'bucketEncryption';
        var bucketNameArr = resource.split(':');
        var bucketName = bucketNameArr[bucketNameArr.length - 1];

        // find the location of the bucket needing to be remediated
        var bucketLocations = cache['s3']['getBucketLocation'];
        var bucketLocation;

        for (var key in bucketLocations) {
            if (bucketLocations[key][bucketName]) {
                bucketLocation = key;
                break;
            }
        }

        // add the location of the bucket to the config
        config.region = bucketLocation;
        var params = {};
        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.kmsKeyId) {
            params = {
                'Bucket': bucketName,
                'ServerSideEncryptionConfiguration': {
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': config.kmsKeyId
                        }
                    }]
                }
            };
        } else {
            params = {
                'Bucket': bucketName,
                'ServerSideEncryptionConfiguration': {
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256',
                        }
                    }]
                }
            };
        }

        var remediation_file = settings.remediation_file;

        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Encryption': 'Disabled',
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
                'Action': 'ENCRYPTED',
                'Bucket': bucketName
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    },

    rollback: function(config, cache, settings, resource, callback) {
        // the call necessary for the rollback (should be a put or delete call)
        var putCall = this.actions.rollback;
        var pluginName = 'bucketEncryption';

        var params = {};
        var bucketNameArr = resource.split(':');
        var bucketName = bucketNameArr[bucketNameArr.length - 1];
        var remediation_file = settings.remediation_file;
        params['Bucket'] = bucketName;
        settings.connection.region = settings['regions'][resource];
        // runs the rollback
        helpers.remediatePlugin(config, putCall, params, function(err) {
            if (err) {
                return callback(err, null);
            } else {
                let action = params;
                action.rollback = putCall;
                action['Encryption'] = 'DISABLED';
                remediation_file['rollback'][pluginName][resource] = action;
                remediation_file['rollback'][pluginName]['action'] = 'DISABLED';
                settings.remediation_file = remediation_file;
                return callback(null, action);
            }
        });
    }
};
