var expect = require('chai').expect;
const bucketAllUsersPolicy = require('./bucketAllUsersPolicy');

const listBuckets = [
    { 
        Name: 'test-bucket-130',
        CreationDate: '2020-09-10T09:11:40.000Z' 
    }
];

const getBucketPolicy = [
    {
        Policy: '{"Version":"2012-10-17","Statement":[{"Sid":"PublicReadGetObject","Effect":"Allow","Principal":"111122223333","Action":"s3:GetObject","Resource":"arn:aws:s3:::test-bucketallusersacl/*"}]}'
    },
    {
        Policy: '{"Version":"2012-10-17","Statement":[{"Sid":"PublicReadGetObject","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::test-bucketallusersacl/*"}]}'
    },
    {
        Policy: '{"Version":"2012-10-17","Statement":[]}'
    },
    {
        Policy: '{"Version":"2012-10-17"}'
    },
];

const createCache = (buckets, policy) => {
    var bucketName = (buckets && buckets.length) ? buckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    [bucketName]: {
                        data: policy
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
    };
};

const createErrorCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: {
                        message: 'error while listing s3 buckets'
                    },
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket policy'
                    },
                },
            },
        },
    };
};

const createPolicyErrorCache = (buckets) => {
    var bucketName = buckets[0].Name;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                }
            },
            getBucketPolicy: {
                'us-east-1': {
                    [bucketName]: {
                        err: {
                            code: 'NoSuchBucketPolicy'
                        }
                    }
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': null,
            },
            getBucketPolicy: {
                'us-east-1': null,
            },
        },
    };
};

describe('bucketAllUsersPolicy', function () {
    describe('run', function () {
        it('should PASS if S3 bucket policy does not contain any insecure allow statements', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[0]);
            bucketAllUsersPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket policy contains insecure allow statements', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[1]);
            bucketAllUsersPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no S3 buckets to check', function (done) {
            const cache = createCache([]);
            bucketAllUsersPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if bucket policy does not contain any statements', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[2]);
            bucketAllUsersPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no additional bucket policy found', function (done) {
            const cache = createPolicyErrorCache([listBuckets[0]]);
            bucketAllUsersPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if bucket policy is invalid JSON or does not contain valid statements', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[3]);
            bucketAllUsersPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list s3 buckets', function (done) {
            const cache = createErrorCache();
            bucketAllUsersPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if s3 list buckets response is not found', function (done) {
            const cache = createNullCache();
            bucketAllUsersPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
