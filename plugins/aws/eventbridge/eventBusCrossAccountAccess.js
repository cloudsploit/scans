var helpers = require('../../../helpers/aws');
var async = require('async');

module.exports = {
    title: 'Event Bus Cross Account Access',
    category: 'EventBridge',
    description: 'Ensure that event bus is configured to allow access to whitelisted AWS account principals.',
    more_info: 'Event bus policy should be configured to allow access only to whitelisted/trusted cross-account principals.',
    link: 'https://docs.amazonaws.cn/en_us/eventbridge/latest/userguide/eb-event-bus-perms.html',
    recommended_action: 'Configure event bus policies that allow access to whitelisted/trusted cross-account principals.',
    apis: ['EventBridge:listEventBuses', 'STS:getCallerIdentity', 'Organizations:listAccounts'],
    settings: {
        whitelisted_aws_account_principals: {
            name: 'Whitelisted AWS Account Principals',
            description: 'A comma-separated list of trusted cross account principals',
            regex: '^.*$',
            default: ''
        },
        whitelisted_aws_account_principals_regex: {
            name: 'Whitelisted AWS Account Principals Regex',
            description: 'If set, plugin will compare cross account principals against this regex instead of otherwise given comma-separated list' +
                'Example regex: ^arn:aws:iam::(111111111111|222222222222|):.+$',
            regex: '^.*$',
            default: ''
        },
        iam_whitelist_aws_organization_accounts: {
            name: 'Whitelist AWS Organization Accounts',
            description: 'If true, trust all accounts in current AWS organization',
            regex: '^(true|false)$',
            default: 'false'
        }
    },
    
    run: function(cache, settings, callback) {
        var config= {
            whitelisted_aws_account_principals : settings.whitelisted_aws_account_principals || this.settings.whitelisted_aws_account_principals.default,
            whitelisted_aws_account_principals_regex : settings.whitelisted_aws_account_principals_regex || this.settings.whitelisted_aws_account_principals_regex.default,
            iam_whitelist_aws_organization_accounts: settings.iam_whitelist_aws_organization_accounts || this.settings.iam_whitelist_aws_organization_accounts.default
        };
        var makeRegexBased = (config.whitelisted_aws_account_principals_regex.length) ? true : false;
        var whitelistOrganization = (config.iam_whitelist_aws_organization_accounts == 'true'); 
        config.whitelisted_aws_account_principals_regex = new RegExp(config.whitelisted_aws_account_principals_regex);
        var results = [];
        var source = {};
        
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', regions.default, 'data']);

        let organizationAccounts = [];
        if (whitelistOrganization) {
            var listAccounts = helpers.addSource(cache, source,
                ['organizations', 'listAccounts', defaultRegion]);

            if (!listAccounts || listAccounts.err || !listAccounts.data) {
                helpers.addResult(results, 3,
                    `Unable to query organization accounts: ${helpers.addError(listAccounts)}`, defaultRegion);
                return callback(null, results, source);
            }
            organizationAccounts = helpers.getOrganizationAccounts(listAccounts, accountId);
        }
        
        async.each(regions.eventbridge, function(region, rcb){
            var listEventBuses = helpers.addSource(cache, source,
                ['eventbridge', 'listEventBuses', region]);
            
            if (!listEventBuses) return rcb();

            if (listEventBuses.err || !listEventBuses.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Event Bus: ${helpers.addError(listEventBuses)}`, region);
                return rcb();
            }

            if (!listEventBuses.data.length) {
                helpers.addResult(results, 2, 'No Event Bus found', region);
                return rcb();
            }
            
            async.each(listEventBuses.data, function(eventBus, cb){
                
                if (!eventBus.Policy) {
                    helpers.addResult(results, 2, `Event Bus ${eventBus.Name} does not contain cross-account policy statement`, region);
                    return cb();
                }
    
                var statements = helpers.normalizePolicyDocument(eventBus.Policy);
    
                if (!statements){
                    helpers.addResult(results, 3, 'No statement exists for the policy', region);
                    return cb();
                }
                var restrictedAccountPrincipals = [];
                var crossAccountEventBus = false;
    
                statements.forEach(statement => {
                    if (statement.Principal && helpers.crossAccountPrincipal(statement.Principal, accountId)) {
                        crossAccountEventBus = true;
                        var principals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);
                        if (principals.length) {
                            principals.forEach(principal => {
                                if (whitelistOrganization) {
                                    if (organizationAccounts.find(account => principal.includes(account))) return;
                                }
                                if (makeRegexBased) {
                                    if (!config.whitelisted_aws_account_principals_regex.test(principal) &&
                                        !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                                } else if (!config.whitelisted_aws_account_principals.includes(principal) &&
                                        !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                            });
                        }
                        return;
                    }
                });
                if (crossAccountEventBus && !restrictedAccountPrincipals.length) {
                    helpers.addResult(results, 0,
                        `Event bus "${eventBus.Name}" contains trusted account principals only`, region);
                    return cb();
                } else if (crossAccountEventBus) {
                    helpers.addResult(results, 2,
                        `Event bus "${eventBus.Name}" contains these untrusted account principals: ${restrictedAccountPrincipals.join(', ')}`, region);
                    return cb();
                } else {
                    helpers.addResult(results, 2,
                        `Event bus "${eventBus.Name}" does not contain cross-account policy statement`, region);
                    return cb();
                }
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};