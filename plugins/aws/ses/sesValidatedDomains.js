var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SES Validated Domains Flagged',
    category: 'SES',
    description: 'Ensures that only Email Identities are used for verification of identities.',
    more_info: 'SES allows for either domains or email addresses to be valid identities. This checks to ensure that only emails have been verified.',
    recommended_action: 'Remove any domains',
    link: 'https://docs.aws.amazon.com/ses/latest/DeveloperGuide/remove-verified-domain.html',
    apis: ['SES:listIdentities', 'SES:getIdentityVerificationAttributes'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ses, function(region, rcb){
            var listIdentities = helpers.addSource(cache, source,
                ['ses', 'listIdentities', region]);

            if (!listIdentities) return rcb();

            if (listIdentities.err || !listIdentities.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SES identities: ' + helpers.addError(listIdentities), region);
                return rcb();
            }

            if (!listIdentities.data.length) {
                helpers.addResult(results, 0, 'No SES domain identities found', region);
                return rcb();
            }

            var getIdentityVerificationAttributes = helpers.addSource(cache, source,
                ['ses', 'getIdentityVerificationAttributes', region]);

            if (!getIdentityVerificationAttributes ||
                getIdentityVerificationAttributes.err ||
                !getIdentityVerificationAttributes.data) {
                helpers.addResult(results, 3,
                    'Unable to get SES Verification attributes: ' + helpers.addError(getIdentityVerificationAttributes), region);
                return rcb();
            }

            for (i in getIdentityVerificationAttributes.data.VerificationAttributes) {
                var identity = getIdentityVerificationAttributes.data.VerificationAttributes[i];

                if (!identity.VerificationStatus) {
                    helpers.addResult(results, 2, 'Domain identity exists with unknown status', region, i);
                } else if (identity.VerificationStatus == 'Success') {
                    helpers.addResult(results, 2,
                        'Domain identity exists and is verified', region, i);
                } else if (identity.VerificationStatus == 'Pending') {
                    helpers.addResult(results, 2,
                        'Domain identity exists and has verification that is pending', region, i);
                } else if (identity.VerificationStatus == 'Failed') {
                    helpers.addResult(results, 2,
                        'Domain identity exists but verification failed', region, i);
                } else if (identity.VerificationStatus == 'TemporaryFailure') {
                    helpers.addResult(results, 2,
                        'Domain identity exists but verification temporarily failed', region, i);  
                } else {
                    helpers.addResult(results, 2, 'Domain identity exists with unknown status', region, i);

                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};