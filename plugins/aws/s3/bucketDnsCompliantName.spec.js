const expect = require('chai').expect;
var bucketDnsCompliantName = require('./bucketDnsCompliantName');

const listBuckets = [
    {
        "Name": "s3buckettest",
        "CreationDate": "2021-01-09T02:56:31+00:00"
    },
    {
        "Name": "s3.bucket.test",
        "CreationDate": "2021-01-09T02:56:31+00:00"
    },
];

const createCache = (listBuckets, listBucketsErr) => {
    var bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: listBucketsErr,
                    data: listBuckets
                }
            },
            getBucketLocation: {
                'us-east-1': {
                    [bucketName]: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
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
            }
        }
    };
};

const createNullCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': null
            }
        }
    };
};

describe('bucketDnsCompliantName', function () {
    describe('run', function () {
        it('should PASS if S3 bucket name is compliant with DNS naming requirements', function (done) {
            const cache = createCache([listBuckets[0]], null);
            bucketDnsCompliantName.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket name is not complaint with DNS naming requirements', function (done) {
            const cache = createCache([listBuckets[1]], null);
            bucketDnsCompliantName.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no S3 buckets found', function (done) {
            const cache = createCache([]);
            bucketDnsCompliantName.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list S3 buckets', function (done) {
            const cache = createCache(null, { message: "Unable to list buckets" }, null);
            bucketDnsCompliantName.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list S3 buckets response not found', function (done) {
            const cache = createNullCache();
            bucketDnsCompliantName.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});