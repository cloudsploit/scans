var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Public Service Domain',
    category: 'ES',
    description: 'Ensures ElasticSearch domains are created with private VPC endpoint options',
    more_info: 'ElasticSearch domains can either be created with a public endpoint or with a VPC configuration that enables internal VPC communication. Domains should be created without a public endpoint to prevent potential public access to the domain.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html',
    recommended_action: 'Configure the ElasticSearch domain to use a VPC endpoint for secure VPC communication.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain'],
    settings: {
        allow_public_only_if_ip_condition_policy: {
            name: 'Allow Public Only If Ip Condition Policy',
            description: 'Allows public ElasticSearch endpoints if set to true and if there is an Ip Condition policy',
            default: false
        },
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var config = {allow_public_only_if_ip_condition_policy: settings.allow_public_only_if_ip_condition_policy || this.settings.allow_public_only_if_ip_condition_policy.default};

        async.each(regions.es, function (region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['es', 'listDomainNames', region]);

            if (!listDomainNames) return rcb();

            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for ES domains: ' + helpers.addError(listDomainNames), region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No ES domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(function(domain){
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region);
                } else {
                    var policies = helpers.normalizePolicyDocument(describeElasticsearchDomain.data.AccessPolicies);
                    var containsIpPolicy = false;

                    for (p in policies) {
                        var policy = policies[p]
                        if (policy.Condition && policy.Condition.IpAddress) {
                            containsIpPolicy = true;
                        }
                    }
                    
                    var localDomain = describeElasticsearchDomain.data.DomainStatus;

                    if (localDomain.VPCOptions &&
                        localDomain.VPCOptions.VPCId &&
                        localDomain.VPCOptions.VPCId.length) {
                        helpers.addResult(results, 0,
                            'ES domain is configured to use a VPC endpoint', region, localDomain.ARN);
                    } else {
                        if (containsIpPolicy && config.allow_public_only_if_ip_condition_policy) {
                            helpers.addResult(results, 0,
                                'ES domain is configured to use a public endpoint, but contains an Ip Condition policy', region, localDomain.ARN);
                        } else {
                            helpers.addResult(results, 2,
                                'ES domain is configured to use a public endpoint', region, localDomain.ARN);
                        }

                    }
                }
            });

            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};
