var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Bucket Cross Organization Access',
    category: 'S3',
    description: 'Ensure that S3 buckets are configured only to allow access to whitelisted AWS account principals.',
    more_info: 'S3 bucket policy should be configured to allow access only to whitelisted/trusted cross-account principals.',
    recommended_action: 'Add bucket policy to manage cross-account access.',
    link: 'https://aws.amazon.com/premiumsupport/knowledge-center/cross-account-access-s3/',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy', 'STS:getCallerIdentity', 'Organizations:listAccounts'],
    settings: {
        s3_whitelisted_aws_account_principals: {
            name: 'S3 Whitelisted AWS Account Principals',
            description: 'A comma-separated list of trusted cross account principals',
            regex: '^.*$',
            default: ''
        },
        s3_whitelisted_aws_account_principals_regex: {
            name: 'S3 Whitelisted AWS Account Principals Regex',
            description: 'If set, plugin will compare cross account principals against this regex instead of otherwise given comma-separated list' +
                'Example regex: ^arn:aws:iam::(111111111111|222222222222|):.+$',
            regex: '^.*$',
            default: ''
        },
        s3_whitelisted_aws_organization_accounts: {
            name: 'S3 Whitelist AWS Organization Accounts',
            description: 'If true, trust all accounts in current AWS organization',
            regex: '^(true|false)$',
            default: 'false'
        },
        s3_policy_condition_keys: {
            name: 'S3 Policy Allowed Condition Keys',
            description: 'Comma separated list of AWS IAM condition keys that should be allowed i.e. aws:SourceAccount,aws:PrincipalArn',
            regex: '^.*$',
            default: 'aws:PrincipalArn,aws:PrincipalAccount,aws:PrincipalOrgID,aws:SourceAccount,aws:SourceArn,aws:SourceOwner'
        },
    },
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. If PCI-restricted data is stored in S3, ' +
             'those buckets should not enable global user access.'
    },


    run: function(cache, settings, callback) {
        var config= {
            s3_whitelisted_aws_account_principals : settings.s3_whitelisted_aws_account_principals || this.settings.s3_whitelisted_aws_account_principals.default,
            s3_whitelisted_aws_account_principals_regex : settings.s3_whitelisted_aws_account_principals_regex || this.settings.s3_whitelisted_aws_account_principals_regex.default,
            s3_whitelisted_aws_organization_accounts: settings.s3_whitelisted_aws_organization_accounts || this.settings.s3_whitelisted_aws_organization_accounts.default,
            s3_policy_condition_keys: settings.s3_policy_condition_keys || this.settings.s3_policy_condition_keys.default
        };
        var makeRegexBased = (config.s3_whitelisted_aws_account_principals_regex.length) ? true : false;
        var whitelistOrganization = (config.s3_whitelisted_aws_organization_accounts == 'true'); 
        var allowedConditionKeys = config.s3_policy_condition_keys.split(',');
        config.s3_whitelisted_aws_account_principals_regex = new RegExp(config.s3_whitelisted_aws_account_principals_regex);
        var results = [];
        var source = {};
        
        var region = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region, 'data']);

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }

        let organizationAccounts = [];
        if (whitelistOrganization) {
            var listAccounts = helpers.addSource(cache, source,
                ['organizations', 'listAccounts', region]);
            if (!listAccounts || listAccounts.err || !listAccounts.data) {
                helpers.addResult(results, 3,
                    `Unable to query organization accounts: ${helpers.addError(listAccounts)}`, region);
                return callback(null, results, source);
            }

            organizationAccounts = helpers.getOrganizationAccounts(listAccounts, accountId);
        }

        listBuckets.data.forEach(bucket => {
            if (!bucket.Name) return;

            var bucketResource = 'arn:aws:s3:::' + bucket.Name;

            var getBucketPolicy = helpers.addSource(cache, source,
                ['s3', 'getBucketPolicy', region, bucket.Name]);
            
            if (!getBucketPolicy.data){
                helpers.addResult(results, 0, 'No custom bucket policy exists', 'global', bucketResource);
                return;
            }
            
            var statements = helpers.normalizePolicyDocument(getBucketPolicy.data.Policy);
            if (!statements) {
                helpers.addResult(results, 3,
                    `Bucket "${bucket.Name}" does not contain any policy statement`,
                    'global', bucketResource);
                return;
            }
            var restrictedAccountPrincipals = [];
            var crossAccountBucket = false;
            
            statements.forEach(statement => {
                if (!statement.Principal) return;
                
                let conditionalPrincipals = helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, true, accountId);
                if (helpers.crossAccountPrincipal(statement.Principal, accountId) ||
                    (conditionalPrincipals && conditionalPrincipals.length)) {
                    
                    let crossAccountPrincipals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);

                    if (conditionalPrincipals && conditionalPrincipals.length) {
                        conditionalPrincipals.forEach(conPrincipal => {
                            if (!conPrincipal.includes(accountId)) crossAccountPrincipals.push(conPrincipal);
                        });
                    }

                    if (!crossAccountPrincipals.length) return;
                    
                    crossAccountBucket = true;
                    
                    crossAccountPrincipals.forEach(principal => {
                        if (whitelistOrganization) {
                            if (organizationAccounts.find(account => principal.includes(account))) return;
                        }
                        if (makeRegexBased) {
                            if (!config.s3_whitelisted_aws_account_principals_regex.test(principal) &&
                                !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                        } else if (!config.s3_whitelisted_aws_account_principals.includes(principal) &&
                                !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                    });
                    return;
                }
            });
            if (crossAccountBucket && !restrictedAccountPrincipals.length) {
                helpers.addResult(results, 0,
                    `Bucket "${bucket.Name}" contains trusted account principals only`,
                    'global', bucketResource);
            } else if (crossAccountBucket) {
                helpers.addResult(results, 2,
                    `Bucket "${bucket.Name}" contains these untrusted account principals: ${restrictedAccountPrincipals.join(', ')}`,
                    'global', bucketResource);
            } else {
                helpers.addResult(results, 2,
                    `Bucket "${bucket.Name}" does not contain cross-account policy statement`,
                    'global', bucketResource);
            }
        });
        callback(null, results, source);
    }    
};
