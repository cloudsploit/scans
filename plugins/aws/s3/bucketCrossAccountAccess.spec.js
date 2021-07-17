var expect = require('chai').expect;
const bucketCrossAccountAccess = require('./bucketCrossAccountAccess');

const listBuckets = [
    { 
        Name: 'test-bucket-130',
        CreationDate: '2020-09-10T09:11:40.000Z' 
    }
];

const organizationAccounts = [
    {
        "Id": "111111111111",
        "Arn": "arn:aws:organizations::111111111111:account/o-sb9qmv2zif/111111111111",
        "Email": "xyz@gmail.com",
        "Name": "test-role",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": "2020-12-27T10:47:14.057Z"
    },
    {
        "Id": "211111111111",
        "Arn": "arn:aws:organizations::211111111111:account/o-sb9qmv2zif/211111111111",
        "Email": "xyz@gmail.com",
        "Name": "test-role",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": "2020-12-27T10:47:14.057Z"
    }
]

const getBucketPolicy = [
    {
        Policy: '{"Version": "2012-10-17", "Statement": [{ "Sid": "AllowGetObject","Effect": "Allow","Principal": {"AWS": ["arn:aws:iam::211111111111:user/x","arn:aws:iam::211111111111:user/y"]},"Action": "s3:GetObject","Resource": "arn:aws:s3:::test-bucket-130/*","Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-sdfasdfdsg546476"}}}]}'
    },
    {
        Policy: '{"Version": "2012-10-17", "Statement": [{ "Sid": "AllowGetObject","Effect": "Allow","Principal": {"AWS": ["arn:aws:iam::111111111111:user/x","arn:aws:iam::111111111111:user/y"]},"Action": "s3:GetObject","Resource": "arn:aws:s3:::test-bucket-130/*","Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-sdfasdfdsg546476"}}}]}'
    },
    {
        Policy: '{"Version":"2012-10-17","Statement":[{"Sid":"PublicReadGetObject","Effect":"Allow","Principal":{"AWS": "arn:aws:iam::111111111111:*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::test-bucketallusersacl/*"}]}'
    },
    {
        Policy: '{"Version":"2012-10-17","Statement":[]}'
    },
    {
        Policy: '{"Version":"2012-10-17"}'
    },
];

const createCache = (buckets, policy, accounts) => {
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
            }
        },
        organizations: {
            listAccounts: {
                'us-east-1': {
                    data: accounts,
                }
            },
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '111111111111'
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
            listAccounts: {
                'us-east-1': {
                    err: {
                        message: 'error while getting organization accounts'
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

describe('bucketCrossAccountAccess', function () {
    describe('run', function () {
        it('should PASS if S3 bucket policy contains policy to allow cross-account access to whitelisted accounts', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[0]);
            bucketCrossAccountAccess.run(cache, {
                "s3_whitelisted_aws_account_principals": [
                    'arn:aws:iam::211111111111:user/x',
                    'arn:aws:iam::211111111111:user/y',
                ]
            }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if cross-account role contains organization account ID and setting to allow organization account is true', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[0], [organizationAccounts[1]]);
            bucketCrossAccountAccess.run(cache, { s3_whitelisted_aws_organization_accounts: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if S3 bucket policy does not contain policy to allow cross-account access', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[2]);
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no S3 buckets to check', function (done) {
            const cache = createCache([]);
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if bucket policy does not contain any statements', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[3]);
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should Fail if no bucket policy found', function (done) {
            const cache = createPolicyErrorCache([listBuckets[0]]);
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if bucket policy is invalid JSON or does not contain valid statements', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[4]);
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list s3 buckets', function (done) {
            const cache = createErrorCache();
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if s3 list buckets response is not found', function (done) {
            const cache = createNullCache();
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
