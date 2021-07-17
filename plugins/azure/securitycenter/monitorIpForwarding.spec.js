var expect = require('chai').expect;
var monitorIpForwarding = require('./monitorIpForwarding');

const policyAssignments = [
    {
        'id': '/subscriptions/123/providers/Microsoft.Authorization/policyAssignments/456',
        'displayName': 'Test Policy',
        'type': 'Microsoft.Authorization/policyAssignments',
        'name': '456',
        'location': 'eastus'
    },
    {
        'id': '/subscriptions/123/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn',
        'displayName': 'ASC Default (subscription: 123)',
        'type': 'Microsoft.Authorization/policyAssignments',
        'name': 'SecurityCenterBuiltIn',
        'location': 'eastus',
        'parameters': {
            'disableIPForwardingMonitoringEffect': {
                'value': 'AuditIfNotExists'
            }
        }
    },
    {
        'id': '/subscriptions/123/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn',
        'displayName': 'ASC Default (subscription: 123)',
        'type': 'Microsoft.Authorization/policyAssignments',
        'name': 'SecurityCenterBuiltIn',
        'location': 'eastus',
        'parameters': {
            'disableIPForwardingMonitoringEffect': {
                'value': 'Disabled'
            }
        }
    },
    {
        'id': '/subscriptions/123/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn',
        'displayName': 'ASC Default (subscription: 123)',
        'type': 'Microsoft.Authorization/policyAssignments',
        'name': 'SecurityCenterBuiltIn',
        'location': 'eastus',
        'parameters': {
            'testParam': {
                'value': 'Disabled'
            }
        }
    }
];

const createCache = (policyAssignments) => {
    let assignment = {};
    if (policyAssignments) {
        assignment['data'] = policyAssignments;
    }
    return {
        policyAssignments: {
            list: {
                'eastus': assignment
            }
        },
    };
};

describe('monitorIpForwarding', function() {
    describe('run', function() {
        it('should give passing result if no policy assignments', function(done) {
            const cache = createCache([]);
            monitorIpForwarding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Policy Assignments found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Policy Assignments', function(done) {
            const cache = createCache(null);
            monitorIpForwarding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Policy Assignments');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if There are no ASC Default Policy Assignments', function(done) {
            const cache = createCache([policyAssignments[0]]);
            monitorIpForwarding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('There are no ASC Default Policy Assignments');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if IP Forwarding Monitoring is enabled', function(done) {
            const cache = createCache([policyAssignments[1]]);
            monitorIpForwarding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('IP Forwarding Monitoring is enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if IP Forwarding Monitoring is disabled', function(done) {
            const cache = createCache([policyAssignments[2]]);
            monitorIpForwarding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('IP Forwarding Monitoring is disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if external accounts with write permissions monitoring is enabled by default', function (done) {
            const cache = createCache([policyAssignments[3]]);
            monitorIpForwarding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('IP Forwarding Monitoring is enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});