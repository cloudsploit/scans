var expect = require('chai').expect;
var bucketEnforceEncryption = require('./bucketEnforceEncryption');

const createCache = (err, data) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }]
                }
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        err: err,
                        data: data
                    }
                }
            },
            getBucketLocation: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        }
    };
};

describe('bucketEnforceEncryption', function () {
    describe('run', function () {
        it('should FAIL if bucket policy is missing', function (done) {
            const cache = createCache({
                code: 'NoSuchBucketPolicy'
            });
            bucketEnforceEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No bucket policy found')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if bucket policy has no data', function (done) {
            const cache = createCache();
            bucketEnforceEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Error querying for bucket policy')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if bucket policy has no statement', function (done) {
            const cache = createCache(null, {
                Policy: JSON.stringify({
                    Statement: []
                })
            });
            bucketEnforceEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket policy does not contain any statements')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if bucket policy has both encryption statements with KMS', function (done) {
            const cache = createCache(null, {
                Policy: JSON.stringify({
                    Statement: [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::mybucket/*",
                            "Condition": {
                                "StringNotEquals": {
                                      "s3:x-amz-server-side-encryption": "aws:kms"
                                }
                            }
                       },
                       {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::mybucket/*",
                            "Condition": {
                                "Null": {
                                    "s3:x-amz-server-side-encryption": true
                                }
                            }
                       }
                    ]
                })
            });
            bucketEnforceEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bucket policy requires encryption on object uploads')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if bucket policy has both encryption statements with x-amz-server-side-encryption', function (done) {
            const cache = createCache(null, {
                Policy: JSON.stringify({
                    Statement: [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::mybucket/*",
                            "Condition": {
                                "StringNotEquals": {
                                      "s3:x-amz-server-side-encryption": "AES256"
                                }
                            }
                       },
                       {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::mybucket/*",
                            "Condition": {
                                "Null": {
                                    "s3:x-amz-server-side-encryption": true
                                }
                            }
                       }
                    ]
                })
            });
            bucketEnforceEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bucket policy requires encryption on object uploads')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if bucket policy has both encryption statements without x-amz-server-side-encryption', function (done) {
            const cache = createCache(null, {
                Policy: JSON.stringify({
                    Statement: [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::mybucket/*",
                            "Condition": {
                                "StringNotEquals": {
                                      "s3:x-amz-server-side-encryption": "AES256"
                                }
                            }
                       },
                       {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::mybucket/*",
                            "Condition": {
                                "Null": {
                                    "s3:x-amz-server-side-encryption": false
                                }
                            }
                       }
                    ]
                })
            });
            bucketEnforceEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket is missing required encryption enforcement policies')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if bucket policy has both encryption statements but AES256 with override', function (done) {
            const cache = createCache(null, {
                Policy: JSON.stringify({
                    Statement: [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::mybucket/*",
                            "Condition": {
                                "StringNotEquals": {
                                      "s3:x-amz-server-side-encryption": "AES256"
                                }
                            }
                       },
                       {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::mybucket/*",
                            "Condition": {
                                "Null": {
                                    "s3:x-amz-server-side-encryption": true
                                }
                            }
                       }
                    ]
                })
            });
            bucketEnforceEncryption.run(cache, {
                s3_enforce_encryption_require_cmk: 'true'
            }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket policy requires encryption on object uploads but is not enforcing AWS KMS type')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if bucket policy has both encryption statements with KMS and override', function (done) {
            const cache = createCache(null, {
                Policy: JSON.stringify({
                    Statement: [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::mybucket/*",
                            "Condition": {
                                "StringNotEquals": {
                                      "s3:x-amz-server-side-encryption": "aws:kms"
                                }
                            }
                       },
                       {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::mybucket/*",
                            "Condition": {
                                "Null": {
                                    "s3:x-amz-server-side-encryption": true
                                }
                            }
                       }
                    ]
                })
            });
            bucketEnforceEncryption.run(cache, {
                s3_enforce_encryption_require_cmk: 'true'
            }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bucket policy requires encryption on object uploads')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if bucket name is whitelisted via override', function (done) {
            const cache = createCache(null, {
                Policy: JSON.stringify({})
            });
            bucketEnforceEncryption.run(cache, {
                s3_enforce_encryption_allow_pattern: '^mybucket$'
            }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is whitelisted via custom setting')
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
