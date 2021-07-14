const expect = require('chai').expect;
var eventBusCrossAccountAccess = require('./eventBusCrossAccountAccess');

const listEventBuses = [
    {
        Name: 'test-bus',
        Arn: 'arn:aws:events:us-east-1:211111111111:event-bus/test-bus',
        Policy: '{"Version":"2012-10-17","Statement":[{"Sid":"allow_account_to_put_events","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::211111111111:user/y"},"Action":"events:PutEvents","Resource":"arn:aws:events:us-east-1:111111111111:event-bus/test-bus"}]}'
    },
    {
        Name: 'test-bus',
        Arn: 'arn:aws:events:us-east-1:111111111111:event-bus/test-bus',
        Policy: '{"Version":"2012-10-17","Statement":[{"Sid":"allow_account_to_put_events","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/x"},"Action":"events:PutEvents","Resource":"arn:aws:events:us-east-1:111111111111:event-bus/test-bus"}]}'
    },
    {
        Name: 'test-bus',
        Arn: 'arn:aws:events:us-east-1:111111111111:event-bus/test-bus',
    },
];

const organizationAccounts = [
    {
        "Id": "211111111111",
        "Arn": "arn:aws:organizations::211111111111:account/o-sb9qmv2zif/111111111111",
        "Email": "xyz@gmail.com",
        "Name": "test-role",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": "2020-12-27T10:47:14.057Z"
    },
    {
        "Id": "123456654322",
        "Arn": "arn:aws:organizations::123456654322:account/o-sb9qmv2zif/123456654322",
        "Email": "xyz@gmail.com",
        "Name": "test-role",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": "2020-12-27T10:47:14.057Z"
    }
]

const createCache = (eventBus, accounts, eventBusErr) => {
    return {
        eventbridge: {
            listEventBuses: {
                'us-east-1': {
                    data: eventBus,
                    err: eventBusErr
                }
            }
        },
        sts: {
            getCallerIdentity: {
                'us-east-1':{
                    data: '111111111111'
                }
            }
        },
        organizations: {
            listAccounts: {
                'us-east-1': {
                    data: accounts
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        eventbridge: {
            listEventBuses: {
                'us-east-1': null
            }
        }
    };
};

describe('eventBusCrossAccountAccess', function () {
    describe('run', function () {

        it('should PASS if Event Bus has cross-account access policy attached', function (done) {
            const cache = createCache([listEventBuses[0]]);
            eventBusCrossAccountAccess.run(cache, {"whitelisted_aws_account_principals":['arn:aws:iam::211111111111:user/y']}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if cross-account role contains organization account ID and setting to allow organization account is true', function (done) {
            const cache = createCache([listEventBuses[0]], [organizationAccounts[0]]);
            eventBusCrossAccountAccess.run(cache, { iam_whitelist_aws_organization_accounts: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if Event Bus does not have cross-account access policy attached', function (done) {
            const cache = createCache([listEventBuses[1]]);
            eventBusCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should FAIL if no Event Bus policy found', function (done) {
            const cache = createCache(listEventBuses[2]);
            eventBusCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if no Event Bus found', function (done) {
            const cache = createCache([]);
            eventBusCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe RDS instances', function (done) {
            const cache = createCache([], {},{ message: 'Unable to describe instances' });
            eventBusCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should not return anything if describe DB instances response not found', function (done) {
            const cache = createNullCache();
            eventBusCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});