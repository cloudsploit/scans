var expect = require('chai').expect;
var bucketCmkEncrypted = require('./bucketCmkEncrypted.js');

const listBuckets = [
    {
        "name": "aqua-test-bucket",
        "region": "oss-cn-hangzhou",
        "creationDate": "2021-05-03T11:53:13.000Z",
        "storageClass": "Standard",
        "StorageClass": "Standard",
        "tag": {}
    },
];

const getBucketInfo = [
    {
        "Name": "aqua-test-bucket",
        "ServerSideEncryptionRule": {
          "KMSMasterKeyID": "ed204e08-f814-4788-8406-3dc19c8e5260",
          "SSEAlgorithm": "KMS"
        }
    },
    {
        "Location": "oss-cn-hangzhou",
        "Name": "aqua-test-bucket",
        "ServerSideEncryptionRule": {
          "KMSMasterKeyID": "",
          "SSEAlgorithm": "KMS"
        }
    },
    {
        "Location": "oss-cn-hangzhou",
        "Name": "aqua-test-bucket",
        "ServerSideEncryptionRule": {
          "SSEAlgorithm": "AES256"
        }
    },
    {
        "Location": "oss-cn-hangzhou",
        "Name": "aqua-test-bucket",
        "ServerSideEncryptionRule": {
          "SSEAlgorithm": "None"
        }
    }
];

const createCache = (listBuckets, getBucketInfo, listBucketsErr, getBucketInfoErr) => {
    let bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].name : null;
    return {
        oss: {
            listBuckets: {
                'cn-hangzhou': {
                    data: listBuckets,
                    err: listBucketsErr
                },
            },
            getBucketInfo: {
                'cn-hangzhou': {
                    [bucketName]: {
                        data: getBucketInfo,
                        err: getBucketInfoErr
                    }
                }
            }
        },
        kms: {
            ListKeys: {
                'cn-hangzhou': {
                    data: [
                        {
                            "KeyId": "ed204e08-f814-4788-8406-3dc19c8e5260",
                            "KeyArn": "acs:kms:cn-hangzhou:0000111122223333:key/ed204e08-f814-4788-8406-3dc19c8e5260"
                        }
                    ]
                }
            },
            DescribeKey: {
                'cn-hangzhou': {
                    "ed204e08-f814-4788-8406-3dc19c8e5260": {
                        "data": {
                            "CreationDate": "2021-05-03T11:11:47Z",
                            "Description": "",
                            "KeyId": "ed204e08-f814-4788-8406-3dc19c8e5260",
                            "KeySpec": "Aliyun_AES_256",
                            "KeyState": "Enabled",
                            "KeyUsage": "ENCRYPT/DECRYPT",
                            "PrimaryKeyVersion": "9e42450c-fe3a-4bc0-93b5-e8074aa4b4c9",
                            "DeleteDate": "",
                            "Creator": "Ecs",
                            "Arn": "acs:kms:cn-hangzhou:0000111122223333:key/ed204e08-f814-4788-8406-3dc19c8e5260",
                            "Origin": "Aliyun_KMS",
                            "MaterialExpireTime": "",
                            "ProtectionLevel": "SOFTWARE",
                            "LastRotationDate": "2021-05-03T11:11:47Z",
                            "AutomaticRotation": "Disabled",
                            "DeletionProtection": "Disabled"
                        }
                    }
                }
            }
        }
    };
};

describe('bucketCmkEncrypted', function () {
    describe('run', function () {
        it('should FAIL if OSS bucket is not encrypted to required encryption level', function (done) {
            const cache = createCache(listBuckets, getBucketInfo[1]);
            bucketCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OSS bucket is server-side encrypted');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should FAIL if OSS bucket is not encrypted', function (done) {
            const cache = createCache(listBuckets, getBucketInfo[3]);
            bucketCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OSS bucket is not server-side encrypted');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if OSS bucket is encrypted to required encryption level', function (done) {
            const cache = createCache(listBuckets, getBucketInfo[0]);
            bucketCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OSS bucket is server-side encrypted');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no OSS buckets found', function (done) {
            const cache = createCache([]);
            bucketCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No OSS buckets found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query for OSS buckets', function (done) {
            const cache = createCache([], null, { err: 'Unable to query for OSS buckets' });
            bucketCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for OSS buckets');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query OSS bucket info', function (done) {
            const cache = createCache(listBuckets, {}, null, { err: 'Unable to query OSS bucket info' });
            bucketCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query OSS bucket info');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 