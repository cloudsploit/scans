var expect = require('chai').expect;
const bucketVersioning = require('./bucketVersioning');

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

const getBucketVersioning = [
    { 
        Status: 'Enabled' 
    },
    {}
];

const createCache = (buckets, versioning) => {
    var bucketName = (buckets && buckets.length) ? buckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                },
            },
            getBucketVersioning: {
                'us-east-1': {
                    [bucketName]: {
                        data: versioning
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
            getBucketVersioning: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket versioning'
                    },
                },
            },
        },
    };
};

const createBucketVersioningErrorCache = (buckets) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                },
            },
            getBucketVersioning: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket versioning'
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
            getBucketVersioning: {
                'us-east-1': null,
            },
        },
    };
};

describe('bucketVersioning', function () {
    describe('run', function () {
        it('should PASS if S3 bucket has object versioning enabled', function (done) {
            const cache = createCache([listBuckets[0]], getBucketVersioning[0]);
            bucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket has object versioning disabled', function (done) {
            const cache = createCache([listBuckets[0]], getBucketVersioning[1]);
            bucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no S3 bucket found', function (done) {
            const cache = createCache([]);
            bucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list s3 buckets', function (done) {
            const cache = createErrorCache();
            bucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to get bucket versioning', function (done) {
            const cache = createBucketVersioningErrorCache([listBuckets[0]]);
            bucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if s3 list buckets response is not found', function (done) {
            const cache = createNullCache();
            bucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});