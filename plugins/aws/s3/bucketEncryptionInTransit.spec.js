var expect = require('chai').expect;
var bucketEncryptionInTransit = require('./bucketEncryptionInTransit');

const createCacheUnparsed = (statement) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: {
                                Version: '2008-10-17',
                                Statement: statement ? [statement] : [],
                            },
                        },
                    },
                },
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
        },
    };
}
const createCache = (statement) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: JSON.stringify({
                                Version: '2008-10-17',
                                Statement: statement ? [statement] : [],
                            }),
                        },
                    },
                },
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
        },
    };
};

const createCacheNoBucketPolicy = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        err: {
                            code: 'NoSuchBucketPolicy',
                        },
                    },
                },
            },
        },
    };
};

const createCacheErrorListBuckets = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: {
                        message: 'bad error',
                    },
                },
            },
        },
    };
};

const createCacheNoBuckets = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [],
                },
            },
        },
    };
};

describe('bucketEncryptionInTransit', function () {
    describe('run', function () {
        it('should FAIL when there are no bucket policy', function (done) {
            const cache = createCacheNoBucketPolicy();
            bucketEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN when there is an error listing buckets', function (done) {
            const cache = createCacheErrorListBuckets();
            bucketEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS when there are no buckets', function (done) {
            const cache = createCacheNoBuckets();
            bucketEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS when there is a statement that denies insecure requests', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: '*',
                Action: 's3:*',
                Resource: [
                    'arn:aws:s3:::mybucket/*',
                    'arn:aws:s3:::mybucket',
                ],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                },
            });
            bucketEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS when there is a statement that denies insecure requests when the policy is parsed', function (done) {
            const cache = createCacheUnparsed({
                Effect: 'Deny',
                Principal: '*',
                Action: 's3:*',
                Resource: [
                    'arn:aws:s3:::mybucket/*',
                    'arn:aws:s3:::mybucket',
                ],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                },
            });
            bucketEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if no deny', function (done) {
            const cache = createCache({
                Effect: 'Allow',
                Principal: '*',
                Action: '*',
                Resource: '*',
            });
            bucketEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if explicit deny all with secure condition but no * principal', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: { Service: 'ec2.amazonaws.com' },
                Action: ['s3:GetObject'],
                Resource: ['arn:aws:s3:::mybucket/*'],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                },
            });
            bucketEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if explicit deny all with secure condition but not on s3:GetObject', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: '*',
                Action: ['s3:PutObject'],
                Resource: ['arn:aws:s3:::mybucket/*'],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                },
            });
            bucketEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if explicit deny all with secure condition but not on all objects', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: '*',
                Action: ['s3:GetObject'],
                Resource: ['arn:aws:s3:::mybucket/mypath/*'],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                },
            });
            bucketEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if explicit deny all with reversed condition', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: '*',
                Action: ['s3:GetObject'],
                Resource: ['arn:aws:s3:::mybucket/*'],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'true' },
                },
            });
            bucketEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
