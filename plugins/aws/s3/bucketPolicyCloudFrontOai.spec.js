var expect = require('chai').expect;
const bucketPolicyCloudFrontOai = require('./bucketPolicyCloudFrontOai');

const listBuckets = [
    {
        "Name": "my.bucket.aqua",
        "CreationDate": "2021-01-10T13:45:10.000Z"
    },
    {
        "Name": "cdn-data",
        "CreationDate": "2020-11-30T10:43:10.000Z"
    },
    {
        "Name": "cdn-oai",
        "CreationDate": "2020-11-30T10:43:10.000Z"
    }
];

const getBucketPolicy = [
    {
        "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"PolicyForCloudFrontPrivateContent\",\"Statement\":[{\"Sid\":\"1\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E1GFXAXB2CIBLG\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::my.bucket.akhtar/*\"}]}"
    },
    {
        "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"PolicyForCloudFrontPrivateContent\",\"Statement\":[{\"Sid\":\"1\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::000011112222:root\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::my.bucket.akhtar/*\"}]}"
    },
    {
        "Policy": null
    }
];

const listDistributions = [
    {
        "Id": "E1MAXX9WRS9EF1",
        "DomainName": "dyfdsiscpe8ax.cloudfront.net",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "ELB-alb-1-384199277",
                    "DomainName": "alb-1-384199277.us-east-1.elb.amazonaws.com"
               }
            ]
        },
    },
    {
        "Id": "E16OS977N7ZR5X",
        "DomainName": "d1pu9fj4y91pww.cloudfront.net",
        "Aliases": {
            "Quantity": 0
        },
        "Origins": {
            "Quantity": 2,
            "Items": [
                {
                    "Id": "S3-my.bucket.aqua/cdn-1",
                    "DomainName": "my.bucket.aqua.s3.amazonaws.com",
                    "OriginPath": "/cdn-1",
                    "CustomHeaders": {
                        "Quantity": 0
                    },
                    "S3OriginConfig": {
                        "OriginAccessIdentity": "origin-access-identity/cloudfront/E1GFXAXB2CIBLG"
                    },
                    "ConnectionAttempts": 3,
                    "ConnectionTimeout": 10
                }
            ]
        }
    },
    {
        "Id": "E16OS977N77TVS",
        "DomainName": "d1pu9fj4y91pww.cloudfront.net",
        "Aliases": {
            "Quantity": 0
        },
        "Origins": {
            "Quantity": 2,
            "Items": [
                {
                    "Id": "S3-cdn-data/cdn-1",
                    "DomainName": "cdn-data.s3.amazonaws.com",
                    "OriginPath": "/cdn-1",
                    "CustomHeaders": {
                        "Quantity": 0
                    },
                    "S3OriginConfig": {
                        "OriginAccessIdentity": "origin-access-identity/cloudfront/E1GFXAXB2CIBLG"
                    },
                    "ConnectionAttempts": 3,
                    "ConnectionTimeout": 10
                }
            ]
        }
    },
    {
        "Id": "E16OS978FTE8VS",
        "DomainName": "d1pu9fj4y91pww.cloudfront.net",
        "Aliases": {
            "Quantity": 0
        },
        "Origins": {
            "Quantity": 2,
            "Items": [
                {
                    "Id": "S3-cdn-data/cdn-1",
                    "DomainName": "cdn-data.s3.amazonaws.com",
                    "OriginPath": "/cdn-1",
                    "CustomHeaders": {
                        "Quantity": 0
                    },
                    "S3OriginConfig": {
                        "OriginAccessIdentity": "origin-access-identity/cloudfront/E1GFXAXB2CIBLG"
                    },
                    "ConnectionAttempts": 3,
                    "ConnectionTimeout": 10
                }
            ]
        }
    },
    {
        "Id": "E16OS978FTE8VS",
        "DomainName": "d1pu9fj4y91pww.cloudfront.net",
        "Aliases": {
            "Quantity": 0
        },
        "Origins": {
            "Quantity": 2,
            "Items": [
                {
                    "Id": "S3-cdn-data/cdn-1",
                    "DomainName": "cdn-data.s3.amazonaws.com",
                    "OriginPath": "/cdn-1",
                    "CustomHeaders": {
                        "Quantity": 0
                    },
                    "S3OriginConfig": {
                        "OriginAccessIdentity": ""
                    },
                    "ConnectionAttempts": 3,
                    "ConnectionTimeout": 10
                }
            ]
        }
    }
];

const createCache = (listDistributions, listBuckets, getBucketPolicy, policyErr) => {
    var bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: listBuckets
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    [bucketName]: {
                        err: policyErr,
                        data: getBucketPolicy
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    [bucketName]: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        },
        cloudfront: {
            listDistributions: {
                'us-east-1': {
                    data: listDistributions
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: {
                        message: 'error while listing S3 buckets'
                    },
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket logging'
                    },
                },
            },
        },
        cloudfront: {
            listDistributions: {
                'us-east-1': {
                    err: {
                        message: 'Unable to list distributions'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        cloudfront: {
            listDistributions: {
                'us-east-1': null
            }
        }
    };
};

describe('bucketPolicyCloudFrontOai', function () {
    describe('run', function () {
        it('should PASS if no S3 origins found for CloudFront distributions', function (done) {
            const cache = createCache([listDistributions[0]]);
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if S3 bucket is origin to only one CloudFront distribution', function (done) {
            const cache = createCache([listDistributions[1]], [listBuckets[0]], getBucketPolicy[0]);
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket is origin to more than one distributions', function (done) {
            const cache = createCache([listDistributions[2], listDistributions[3]], [listBuckets[1]]);
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket is origin to distribution without an origin access identity', function (done) {
            const cache = createCache([listDistributions[4]]);
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if S3 bucket is origin to dstribution and allows access to unknown sources', function (done) {
            const cache = createCache([listDistributions[1]], [listBuckets[0]], getBucketPolicy[1]);
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket is origin to dstribution and does not allow access to these CloudFront OAIs', function (done) {
            const cache = createCache([listDistributions[1]], [listBuckets[0]], getBucketPolicy[1]);
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if no bucket policy found for S3 bucket', function (done) {
            const cache = createCache([listDistributions[1]], [listBuckets[0]], getBucketPolicy[1], { code: 'NoSuchBucketPolicy' });
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if error while querying S3 bucket', function (done) {
            const cache = createCache([listDistributions[1]], [listBuckets[0]], getBucketPolicy[2]);
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no S3 origins to check', function (done) {
            const cache = createCache([]);
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list CloudFront distributions', function (done) {
            const cache = createErrorCache();
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if list distributions result not found', function (done) {
            const cache = createNullCache();
            bucketPolicyCloudFrontOai.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});