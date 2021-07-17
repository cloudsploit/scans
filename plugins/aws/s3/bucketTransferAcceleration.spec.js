const expect = require('chai').expect;
var bucketTransferAcceleration = require('./bucketTransferAcceleration');

const listBuckets = [
    {
        "Name": "s3buckettest",
        "CreationDate": "2021-01-09T02:56:31+00:00"
    },
];

const getBucketAccelerateConfiguration = [
    {
        Status: 'Enabled'
    },
    {
        Status: 'Suspended'
    }
]

const createCache = (listBuckets, getBucketAccelerateConfiguration, listBucketsErr, getBucketAccelerateConfigurationErr) => {
    var bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: listBucketsErr,
                    data: listBuckets
                }
            },
            getBucketAccelerateConfiguration: {
                'us-east-1': {
                    [bucketName]: {
                        err: getBucketAccelerateConfigurationErr,
                        data: getBucketAccelerateConfiguration
                    }
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

describe('bucketTransferAcceleration', function () {
    describe('run', function () {
        it('should PASS if S3 bucket has transfer acceleration enabled', function (done) {
            const cache = createCache([{Name: 'bucket-1'}], { Status: 'Enabled' }, null, null);
            bucketTransferAcceleration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket does not have transfer acceleration enabled', function (done) {
            const cache = createCache([{Name: 'bucket-1'}], {}, null, null);
            bucketTransferAcceleration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket has transfer acceleration suspended', function (done) {
            const cache = createCache([{Name: 'bucket-1'}], { Status: 'Suspended' }, null);
            bucketTransferAcceleration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no S3 buckets found', function (done) {
            const cache = createCache([]);
            bucketTransferAcceleration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list S3 buckets', function (done) {
            const cache = createCache(null, null, { message: "Unable to list buckets" }, null);
            bucketTransferAcceleration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to get bucket acceleration configuration', function (done) {
            const cache = createCache([{Name: 'bucket-1'}], null, null, { message: "Unable to get bucket acceleration configuration"});
            bucketTransferAcceleration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list S3 buckets response not found', function (done) {
            const cache = createNullCache();
            bucketTransferAcceleration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});