var expect = require('chai').expect;
const bucketLogging = require('./bucketLogging');

const listBuckets = [
    {
        Name: 'elasticbeanstalk-us-east-1-111122223333',
        CreationDate: '2020-08-20T17:42:52.000Z'
    },
    { 
        Name: 'test-bucket-130',
        CreationDate: '2020-09-10T09:11:40.000Z' 
    },
    {
        Name: 'test-bucket-sploit-100',
        CreationDate: '2020-09-06T09:44:16.000Z'
    }
];

const getBucketLogging = [
    {
        LoggingEnabled: {
            TargetBucket: 'test-bucket-130',
            TargetGrants: [],
            TargetPrefix: ''
        }
    },
    {}
];

const createCache = (buckets, logging) => {
    var bucketName = (buckets && buckets.length) ? buckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                },
            },
            getBucketLogging: {
                'us-east-1': {
                    [bucketName]: {
                        data: logging
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
                        message: 'error while listing S3 buckets'
                    },
                },
            },
            getBucketLogging: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket logging'
                    },
                },
            },
        },
    };
};

const createBucketLoggingErrorCache = (buckets) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                },
            },
            getBucketLogging: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket logging'
                    },
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
            getBucketLogging: {
                'us-east-1': null,
            },
        },
    };
};

describe('bucketLogging', function () {
    describe('run', function () {
        it('should PASS if S3 bucket has object logging enabled', function (done) {
            const cache = createCache([listBuckets[0]], getBucketLogging[0]);
            bucketLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket has object logging disabled', function (done) {
            const cache = createCache([listBuckets[0]], getBucketLogging[1]);
            bucketLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no S3 bucket found', function (done) {
            const cache = createCache([]);
            bucketLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list S3 buckets', function (done) {
            const cache = createErrorCache();
            bucketLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe bucket logging', function (done) {
            const cache = createBucketLoggingErrorCache([listBuckets[0]]);
            bucketLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if S3 list buckets response is not found', function (done) {
            const cache = createNullCache();
            bucketLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});