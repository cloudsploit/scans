const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Access Keys Regenerated Periodically',
    category: 'Storage Accounts',
    description: 'Ensures that storage account access keys are being regenerated periodically.',
    more_info: 'Microsoft recommends to rotate storage account access keys periodically(once in 90 days period) to help keep storage accounts secure.',
    recommended_action: 'Regenerate storage account access keys',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal#regenerate-access-keys',
    apis: ['storageAccounts:list', 'activityLogs:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb) {
            const storageAccounts = helpers.addSource(
                cache, source, ['storageAccounts', 'list', location]);

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for storage accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            }

            if (!storageAccounts.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            }

            async.each(storageAccounts.data, function(storageAccount, scb) {
                const activityLogs = helpers.addSource(
                    cache, source, ['activityLogs', 'list', location, storageAccount.id]);

                if (!activityLogs || activityLogs.err || !activityLogs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query activity logs for storage account: ' + helpers.addError(storageAccounts), location, storageAccount.id);
                    return scb();
                }

                if (!activityLogs.data.length) {
                    helpers.addResult(results, 2, 'Storage account access keys were not regenerated in last 90 days', location, storageAccount.id);
                    return scb();
                }

                let regenerated = activityLogs.data.find((log) => {
                    return (log.authorization && log.authorization.action &&
                        log.authorization.action === 'Microsoft.Storage/storageAccounts/regenerateKey/action');
                });

                if (regenerated) {
                    helpers.addResult(results, 0, 'Storage account access keys were regenerated in last 90 days', location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2, 'Storage account access keys were not regenerated in last 90 days', location, storageAccount.id);
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
