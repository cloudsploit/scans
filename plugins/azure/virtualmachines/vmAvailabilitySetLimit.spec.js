var expect = require('chai').expect;
var vmAvailabilitySetLimit = require('./vmAvailabilitySetLimit');

const resourceGroups = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group',
        'name': 'aqua-resource-group',
        'type': 'Microsoft.Resources/resourceGroups',
        'location': 'eastus',
        'tags': {},
        'properties': {
            'provisioningState': 'Succeeded'
        }
    }
];

const availabilitySets = [
    {
        'name': 'test-set',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/availabilitySets/test-set',
        'type': 'Microsoft.Compute/availabilitySets',
        'location': 'eastus',
        'tags': {},
        'platformUpdateDomainCount': 5,
        'platformFaultDomainCount': 2,
        'virtualMachines': [
            {
                'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachines/test-vm-1'
            }
        ],
        'sku': {
            'name': 'Aligned'
        }
    }
];

const createCache = (resourceGroups, availabilitySets) => {
    let group = {};
    let set = {};
    if (resourceGroups) {
        group['data'] = resourceGroups;
        if (resourceGroups.length && availabilitySets) {
            set[resourceGroups[0].id] = {
                data: availabilitySets
            };
        }
    }
    return {
        resourceGroups: {
            list: {
                'eastus': group
            }
        },
        availabilitySets: {
            listByResourceGroup: {
                'eastus': set
            }
        }
    };
};

describe('vmAvailabilitySetLimit', function() {
    describe('run', function() {
        it('should give passing result if No existing resource groups', function(done) {
            const cache = createCache([]);
            vmAvailabilitySetLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Resource Groups');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for resource groups', function(done) {
            const cache = createCache();
            vmAvailabilitySetLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Resource Groups');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if No existing Availability Sets', function(done) {
            const cache = createCache([resourceGroups[0]], []);
            vmAvailabilitySetLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Availability Sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for availability sets', function(done) {
            const cache = createCache([resourceGroups[0]]);
            vmAvailabilitySetLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Availability Sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if vm instances percentage are below the limits', function(done) {
            const cache = createCache([resourceGroups[0]], [availabilitySets[0]]);
            vmAvailabilitySetLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Availability Set contains 1 of 200 (1%) available instances');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing results if number of vm instances has reached the fail limit', function(done) {
            const cache = createCache([resourceGroups[0]], [availabilitySets[0]]);
            const settings = {
                instance_limit_percentage_fail: 1
            };
            vmAvailabilitySetLimit.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Availability Set contains 1 of 200 (1%) available instances');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give warn result if number of vm instances has reached the warn limit', function(done) {
            const cache = createCache([resourceGroups[0]], [availabilitySets[0]]);
            const settings = {
                instance_limit_percentage_warn: 1
            };
            vmAvailabilitySetLimit.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).to.include('Availability Set contains 1 of 200 (1%) available instances');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});