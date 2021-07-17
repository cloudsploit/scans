var helpers = require('../../../helpers/aws');
var async = require('async');

module.exports = {
    title: 'IAM User Account In Use',
    category: 'IAM',
    description: 'Ensure that IAM user accounts are being actively used.',
    more_info: 'IAM users, roles, and groups should be used for day-to-day account management.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html',
    recommended_action: 'Create IAM users with appropriate group-level permissions for account access. Create an MFA token for the IAM user account, and store its password and token generation QR codes in a secure place.',
    apis: ['IAM:generateCredentialReport'],
    settings: {
        iam_user_account_in_use_days: {
            name: 'IAM User Account In Use Days',
            description: 'Return a failing result when the IAM user account has been used within this many days',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 15
        }
    },

    run: function(cache, settings, callback, now) {
        var config = {
            iam_user_account_in_use_days: settings.iam_user_account_in_use_days || this.settings.iam_user_account_in_use_days.default
        };
        var currentDate = now;
        if (!currentDate) currentDate = new Date();

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var generateCredentialReport = helpers.addSource(cache, source,
            ['iam', 'generateCredentialReport', region]);
        
        if (!generateCredentialReport) return callback(null, results, source);

        if (generateCredentialReport.err || !generateCredentialReport.data) {
            helpers.addResult(results, 3,
                'Unable to query IAM users: ' + helpers.addError(generateCredentialReport));
            return callback(null, results, source);
        }

        var found = false;

        async.forEach(generateCredentialReport.data, (user) => {
            if (user && user.user !== '<root_account>') {
                found = true;

                var accessDates = [];

                if (user.password_last_used && user.password_last_used !== 'no_information') {
                    accessDates.push(user.password_last_used);
                }

                if (user.access_key_1_last_used_date) accessDates.push(user.access_key_1_last_used_date);

                if (user.access_key_2_last_used_date) accessDates.push(user.access_key_2_last_used_date);

                if (!accessDates.length) {
                    helpers.addResult(results, 0, 'IAM user has not been used', 'global', user.arn);
                } else {
                    var dateToCompare = helpers.mostRecentDate(accessDates);
                    var resultCode = (helpers.daysBetween(dateToCompare, currentDate) < config.iam_user_account_in_use_days) ? 2: 0;

                    helpers.addResult(results, resultCode,
                        'IAM user was last used ' + helpers.daysBetween(dateToCompare, currentDate) + ' days ago',
                        'global', user.arn, custom);
                }
            }
        });

        if (!found) {
            helpers.addResult(results, 3, 'Unable to query IAM users');
        }

        callback(null, results, source);
    }
};
