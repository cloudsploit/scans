var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Automated Backups Configured',
    category: 'App Service',
    description: 'Ensures that Azure Web Apps have automated backups configured.',
    more_info: 'The Backup and Restore feature in Azure App Service lets you easily create app backups manually or on a schedule.You can restore the app to a snapshot of a previous state by overwriting the existing app or restoring to another app.',
    recommended_action: 'Configure Automated Backups for Azure Web Apps',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/manage-backup',
    apis: ['webApps:list', 'webApps:listBackupConfig'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(cache, source,
                ['webApps', 'list', location]
            );

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3, 'Unable to query for Web Apps: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing Web Apps found', location);
                return rcb();
            }

            async.each(webApps.data, function(webApp, scb) {
                if (webApp.kind && webApp.kind && webApp.kind === 'functionapp') {
                    helpers.addResult(results, 0, 'Backups can not be configured for the function App', location, webApp.id);
                    return scb();
                }

                const backupConfig = helpers.addSource(cache, source,
                    ['webApps', 'listBackupConfig', location, webApp.id]
                );

                if (!backupConfig || backupConfig.err || !backupConfig.data) {
                    helpers.addResult(results, 2, 'Automated Backups are not configured for the webApp', location, webApp.id);
                } else {
                    helpers.addResult(results, 0, 'Automated Backups are configured for the webApp', location, webApp.id);
                }

                scb();
            }, function() {
                rcb();
            });
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};