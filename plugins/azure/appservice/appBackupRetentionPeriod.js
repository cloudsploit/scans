var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Backup Retention Period',
    category: 'App Service',
    description: 'Ensures that Azure Web Apps have a sufficient backup retention period configured.',
    more_info: 'The Backup and Restore feature in Azure App Service lets you easily create app backups manually or on a schedule.You can restore the app to a snapshot of a previous state by overwriting the existing app or restoring to another app.',
    recommended_action: 'Set an optimal backup retention period for app service Web Apps',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/manage-backup',
    apis: ['webApps:list', 'webApps:listBackupConfig'],
    settings: {
        webApp_backup_retention_period: {
            name: 'Azure Web App Backup Retention Period',
            description: 'Desired number of days for which backups will be retained.',
            regex: '^[0-9]*$',
            default: '30'
        }
    },

    run: function(cache, settings, callback) {
        const config = {
            retentionDays: parseInt(settings.webApp_backup_retention_period || this.settings.webApp_backup_retention_period.default)
        };

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
                    'Unable to query for Web Apps: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(
                    results, 0, 'No existing Web Apps found', location);
                return rcb();
            }

            async.each(webApps.data, function(webApp, scb) {
                if (webApp && webApp.kind === 'functionapp') {
                    helpers.addResult(results, 0, 'Backups can not be configured for the function App', location, webApp.id);
                    return scb();
                } else {
                    const backupConfig = helpers.addSource(
                        cache, source, ['webApps', 'listBackupConfig', location, webApp.id]
                    );

                    if (backupConfig && backupConfig.err && backupConfig.err.includes('Backup configuration not found for site')) {
                        helpers.addResult(results, 2, 'Backups are not configured for the Web App',
                            location, webApp.id);
                    } else if (!backupConfig || backupConfig.err || !backupConfig.data) {
                        helpers.addResult(results, 3, `Unable to query app backup config: ${helpers.addError(backupConfig)}`,
                            location, webApp.id);
                        return scb();
                    }

                    if (backupConfig.data) {
                        if (backupConfig.data.backupSchedule &&
                            backupConfig.data.backupSchedule.retentionPeriodInDays &&
                            backupConfig.data.backupSchedule.retentionPeriodInDays >= config.retentionDays) {
                            helpers.addResult(results, 0,
                                `Web App is configured to retain backups for ${backupConfig.data.backupSchedule.retentionPeriodInDays} of ${config.retentionDays} days desired limit`,
                                location, webApp.id);
                        } else {
                            helpers.addResult(results, 2,
                                `Web App is configured to retain backups for ${backupConfig.data.backupSchedule.retentionPeriodInDays} of ${config.retentionDays} days desired limit`,
                                location, webApp.id);
                        }
                    }
                }

                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
