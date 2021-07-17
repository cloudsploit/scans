var expect = require('chai').expect;
var appserviceAutomatedBackups = require('./appserviceAutomatedBackups');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'kind': 'app,linux',
        'location': 'East US'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'kind': 'functionapp',
        'location': 'East US'
    }
];

const backupConfig = {
    'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
    'name': 'test-app',
    'type': 'Microsoft.Web/sites',
    'location': 'East US',
    'backupSchedule': {
        'frequencyInterval': 1,
        'frequencyUnit': 'Day',
        'keepAtLeastOneBackup': true,
        'retentionPeriodInDays': 30,
        'startTime': '2021-05-29T19:58:29.702'
    }
};

const createCache = (webApps, backupConfig) => {
    let app = {};
    let config = {};

    if (webApps) {
        app['data'] = webApps;
        if (webApps && webApps.length) {
            config[webApps[0].id] = backupConfig;
        }
    }

    return {
        webApps: {
            list: {
                'eastus': app
            },
            listBackupConfig: {
                'eastus': config
            }
        }
    };
};

describe('appserviceAutomatedBackups', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            appserviceAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Web Apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web apps', function(done) {
            const cache = createCache();
            appserviceAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web Apps:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if app is a function app', function(done) {
            const cache = createCache([webApps[1]]);
            appserviceAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Backups can not be configured for the function App');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if there is an error in getting backup config', function(done) {
            const cache = createCache([webApps[0]], {
                err: 'Unknown error occurred while calling the Azure API'
            });
            appserviceAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automated Backups are not configured for the webApp');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no app config found', function(done) {
            const cache = createCache([webApps[0]], {});
            appserviceAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automated Backups are not configured for the webApp');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if automated backups are configured', function(done) {
            const cache = createCache([webApps[0]], {
                'data': backupConfig
            });
            appserviceAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automated Backups are configured for the webApp');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});