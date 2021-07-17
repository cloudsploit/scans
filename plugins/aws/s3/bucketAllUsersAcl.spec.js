var expect = require('chai').expect;
const bucketAllUsersAcl = require('./bucketAllUsersAcl');

const listBuckets = [
    { 
        Name: 'test-bucket-130',
        CreationDate: '2020-09-10T09:11:40.000Z' 
    }
];

const getBucketAcl = [
    {
        "Owner": {
            "DisplayName": "aws-test",
            "ID": "91bfbca30b5e6d86faa17a9fdd05ebb1dbbd2c27e6175aeba6ad00bff680d9f5"
        },
        "Grants": [
            {
                "Grantee": {
                    "DisplayName": "aws-test",
                    "ID": "91bfbca30b5e6d86faa17a9fdd05ebb1dbbd2c27e6175aeba6ad00bff680d9f5",
                    "Type": "CanonicalUser"
                },
                "Permission": "FULL_CONTROL"
            },
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"
                },
                "Permission": "WRITE"
            },
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"
                },
                "Permission": "READ_ACP"
            }
        ]
    },
    {
        "Owner": {
            "DisplayName": "aws-test",
            "ID": "91bfbca30b5e6d86faa17a9fdd05ebb1dbbd2c27e6175aeba6ad00bff680d9f5"
        },
        "Grants": [
            {
                "Grantee": {
                    "DisplayName": "aws-test",
                    "ID": "91bfbca30b5e6d86faa17a9fdd05ebb1dbbd2c27e6175aeba6ad00bff680d9f5",
                    "Type": "CanonicalUser"
                },
                "Permission": "FULL_CONTROL"
            },
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                },
                "Permission": "READ"
            }
        ]
    },
    {
        "Owner": {
            "DisplayName": "aws-test",
            "ID": "91bfbca30b5e6d86faa17a9fdd05ebb1dbbd2c27e6175aeba6ad00bff680d9f5"
        },
        "Grants": [
            {
                "Grantee": {
                    "DisplayName": "aws-test",
                    "ID": "91bfbca30b5e6d86faa17a9fdd05ebb1dbbd2c27e6175aeba6ad00bff680d9f5",
                    "Type": "CanonicalUser"
                },
                "Permission": "FULL_CONTROL"
            },
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                },
                "Permission": "WRITE"
            }
        ]
    },
];

const createCache = (buckets, acl) => {
    var bucketName = (buckets && buckets.length) ? buckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                },
            },
            getBucketAcl: {
                'us-east-1': {
                    [bucketName]: {
                        data: acl
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
            getBucketAcl: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket ACL'
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
            getBucketAcl: {
                'us-east-1': null,
            },
        },
    };
};

describe('bucketAllUsersAcl', function () {
    describe('run', function () {
        it('should PASS if S3 bucket does not allow global permissions', function (done) {
            const cache = createCache([listBuckets[0]], getBucketAcl[0]);
            bucketAllUsersAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should WARN if S3 bucket allows any of the global read permissions', function (done) {
            const cache = createCache([listBuckets[0]], getBucketAcl[1]);
            bucketAllUsersAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket allows any of the global write permissions', function (done) {
            const cache = createCache([listBuckets[0]], getBucketAcl[2]);
            bucketAllUsersAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no S3 buckets to check', function (done) {
            const cache = createCache([]);
            bucketAllUsersAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list s3 buckets', function (done) {
            const cache = createErrorCache();
            bucketAllUsersAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should not return any result if s3 list buckets response is not found', function (done) {
            const cache = createNullCache();
            bucketAllUsersAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
        

    });
});