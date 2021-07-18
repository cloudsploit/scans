var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'TLS Version Check',
    category: 'App Service',
    description: 'Ensures that all web apps are using the latest version of TLS',
    more_info: 'App Services currently allows web apps to use TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for web app TLS connections.',
    recommended_action: 'Set the minimum TLS version to 1.2 for all App Services.',
    link: 'https://azure.microsoft.com/en-in/updates/app-service-and-functions-hosted-apps-can-now-update-tls-versions/',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    remediation_min_version: '202107182224',
    remediation_description: 'The TLS version 1.2 will be set for the web app',
    apis_remediate: ['webApps:list'],
    actions: { remediate: ['webApps:updateConfiguration'], rollback: ['webApps:updateConfiguration'] },
    permissions: { remediate: ['webApps:updateConfiguration'], rollback: ['webApps:updateConfiguration'] },
    realtime_triggers: ['microsoftweb:sites:write'],
    compliance: {
        pci: 'PCI requires all web applications encrypt data ' +
            'in transit. This includes using the latest TLS ' +
            'version.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(
                cache, source, ['webApps', 'list', location]
            );

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query for App Services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(
                    results, 0, 'No existing App Services found', location);
                return rcb();
            }

            webApps.data.forEach(function(webApp) {
                const webConfigs = helpers.addSource(
                    cache, source, ['webApps', 'listConfigurations', location, webApp.id]
                );

                if (!webConfigs || webConfigs.err || !webConfigs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query App Service: ' + helpers.addError(webConfigs),
                        location, webApp.id);
                } else {
                    if (webConfigs.data[0] &&
                        webConfigs.data[0].minTlsVersion &&
                        parseFloat(webConfigs.data[0].minTlsVersion) >= parseFloat('1.2')) {
                        helpers.addResult(results, 0, 'Minimum TLS version criteria is satisfied', location, webApp.id);
                    } else {
                        helpers.addResult(results, 2, 'Minimum TLS version is not 1.2', location, webApp.id);
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    },

    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;

        // inputs specific to the plugin
        var pluginName = 'tlsVersionCheck';
        var baseUrl = 'https://management.azure.com/{resource}/config/web?api-version=2019-08-01';
        var method = 'PATCH';

        // for logging purposes
        var webAppNameArr = resource.split('/');
        var webAppName = webAppNameArr[webAppNameArr.length - 1];

        // create the params necessary for the remediation
        if (settings.region) {
            var body = {
                'location': settings.region,
                'properties': {
                    'minTlsVersion': '1.2'
                }

            };
            
            const webConfigs = cache.webApps.listConfigurations[settings.region][resource];
            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                'minTlsVersion': webConfigs.data[0].minTlsVersion,
                'WebApp': webAppName
            };

            helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
                if (err) return callback(err);
                if (action) action.action = putCall;


                remediation_file['post_remediate']['actions'][pluginName][resource] = action;
                remediation_file['remediate']['actions'][pluginName][resource] = {
                    'Action': 'Enabled'
                };

                callback(null, action);
            });
        } else {
            callback('No region found');
        }
    }
};


