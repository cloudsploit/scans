var expect = require('chai').expect;
var accessKeysRegenerated = require('./accessKeysRegenerated');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
    }
];

const activityLogs = [
    {
        'authorization': {
            'action': 'Microsoft.Storage/storageAccounts/regenerateKey/action',
            'scope': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc'
        },
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/events/123/ticks/456'
    },
    {
        'authorization': {
            'action': 'Microsoft.Storage/storageAccounts/listKeys/action',
            'scope': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc'
        },
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/events/123/ticks/456'
    }
];

const createCache = (storageAccounts, activityLogs) => {
    let account = {};
    let log = {};
    if (storageAccounts) {
        account['data'] = storageAccounts;
        if (activityLogs && storageAccounts.length > 0) {
            log[storageAccounts[0].id] = {
                data: activityLogs
            };
        }
    }
    return {
        activityLogs: {
            list: {
                'eastus': log
            }
        },
        storageAccounts: {
            list: {
                'eastus': account
            }
        }
    };
};

describe('accessKeysRegenerated', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([], []);
            accessKeysRegenerated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createCache(null, null);
            accessKeysRegenerated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no activity logs', function(done) {
            const cache = createCache([storageAccounts[0]], []);
            accessKeysRegenerated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage account access keys were not regenerated in last 90 days');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for activity logs', function(done) {
            const cache = createCache([storageAccounts[0]], null);
            accessKeysRegenerated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query activity logs for storage account');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if access keys are regenerated', function(done) {
            const cache = createCache([storageAccounts[0]], [activityLogs[0]]);
            accessKeysRegenerated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage account access keys were regenerated in last 90 days');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if access keys are not regenerated', function(done) {
            const cache = createCache([storageAccounts[0]], [activityLogs[1]]);
            accessKeysRegenerated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage account access keys were not regenerated in last 90 days');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});