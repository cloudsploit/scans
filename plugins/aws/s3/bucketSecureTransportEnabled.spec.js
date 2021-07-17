var expect = require('chai').expect;
const bucketSecureTransportEnabled = require('./bucketSecureTransportEnabled');

const listBuckets = [
    { 
        Name: 'test-bucket-130',
        CreationDate: '2020-09-10T09:11:40.000Z'
    },
    {
        Name: 'elasticbeanstalk-us-east-1-123456654321',
        CreationDate: '2020-08-20T17:42:52.000Z'
    },
    {
      Name: 'test-bucket-sploit-100',
      CreationDate: '2020-09-06T09:44:16.000Z'
    }
];

const getBucketPolicy = [
    {
        Policy: '{"Version":"2012-10-17","Id":"ExamplePolicy","Statement":[{"Sid":"AllowSSLRequestsOnly","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::test-bucket-130","arn:aws:s3:::test-bucket-130/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
    },
    {
        Policy: '{"Version":"2008-10-17","Statement":[{"Sid":"eb-ad78f54a-f239-4c90-adda-49e5f56cb51e","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456654321:role/aws-elasticbeanstalk-ec2-role"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::elasticbeanstalk-us-east-1-123456654321/resources/environments/logs/*"},{"Sid":"eb-af163bf3-d27b-4712-b795-d1e33e331ca4","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456654321:role/aws-elasticbeanstalk-ec2-role"},"Action":["s3:ListBucket","s3:ListBucketVersions","s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::elasticbeanstalk-us-east-1-123456654321","arn:aws:s3:::elasticbeanstalk-us-east-1-123456654321/resources/environments/*"]},{"Sid":"eb-58950a8c-feb6-11e2-89e0-0800277d041b","Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::elasticbeanstalk-us-east-1-123456654321"}]}'
    },
    {
        Policy: '{"Version":"2012-10-17","Id":"ExamplePolicy","Statement":[]}'
    },
];


const createCache = (listBuckets, getBucketPolicy) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: listBuckets
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    [listBuckets[0].Name]: {
                        data: getBucketPolicy
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    [listBuckets[0].Name]: {
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
                        message: 'error while listing buckets'
                    },
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket policy'
                    },
                }
            }
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


describe('bucketSecureTransportEnabled', function () {
    describe('run', function () {
        it('should PASS if S3 bucket enforces SSL to secure data in transit', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[0]);
            bucketSecureTransportEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket policy does not include any statement', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[2]);
            bucketSecureTransportEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket does not enforce SSL to secure data in transit', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[0]);
            bucketSecureTransportEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if error while listing S3 buckets', function (done) {
            const cache = createErrorCache();
            bucketSecureTransportEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if S3 list bucket response is not found', function (done) {
            const cache = createNullCache();
            bucketSecureTransportEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});