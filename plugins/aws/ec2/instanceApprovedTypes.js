var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 Approved Instance Types',
    category: 'EC2',
    description: 'Ensures that running EC2 instances are within the approved types setting.',
    more_info: 'The types of EC2 instances should be carefully audited, to ensure only approved types are launched and consuming compute resources. Many compromised AWS accounts see large EC2 instances launched without approval and overrun costs.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring_ec2.html',
    recommended_action: 'Ensure that the EC2 instances types match the approved types. If instances are launched that do not belong to the approved types, investigate to ensure they are legitimate.',
    apis: ['EC2:describeInstances'],
    settings: {
        disapproved_instance_types_global: {
            name: 'Disapproved Instance Types Global',
            description: 'Checks for unapproved instances across all regions and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_us_east_1: {
            name: 'Disapproved Instance Types Region: us-east-1',
            description: 'Checks for unapproved instances in the us-east-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_us_east_2: {
            name: 'Disapproved Instance Types Region: us-east-2',
            description: 'Checks for unapproved instances in the us-east-2 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_us_west_1: {
            name: 'Disapproved Instance Types Region: us-west-1',
            description: 'Checks for unapproved instances in the us-west-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_us_west_2: {
            name: 'Disapproved Instance Types Region: us-west-2',
            description: 'Checks for unapproved instances in the us-west-2 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ap_northeast_1: {
            name: 'Disapproved Instance Types Region: ap-northeast-1',
            description: 'Checks for unapproved instances in the ap-northeast-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ap_northeast_2: {
            name: 'Disapproved Instance Types Region: ap-northeast-2',
            description: 'Checks for unapproved instances in the ap-northeast-2 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ap_southeast_1: {
            name: 'Disapproved Instance Types Region: ap-southeast-1',
            description: 'Checks for unapproved instances in the ap-southeast-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ap_southeast_2: {
            name: 'Disapproved Instance Types Region: ap-southeast-2',
            description: 'Checks for unapproved instances in the ap-southeast-2 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_eu_central_1: {
            name: 'Disapproved Instance Types Region: eu-central-1',
            description: 'Checks for unapproved instances in the eu-central-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_eu_west_1: {
            name: 'Disapproved Instance Types Region: eu-west-1',
            description: 'Checks for unapproved instances in the eu-west-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_eu_west_2: {
            name: 'Disapproved Instance Types Region: eu-west-2',
            description: 'Checks for unapproved instances in the eu-west-2 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_eu_west_3: {
            name: 'Disapproved Instance Types Region: eu-west-3',
            description: 'Checks for unapproved instances in the eu-west-3 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_sa_east_1: {
            name: 'Disapproved Instance Types Region: sa-east-1',
            description: 'Checks for unapproved instances in the sa-east-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ap_south_1: {
            name: 'Disapproved Instance Types Region: ap-south-1',
            description: 'Checks for unapproved instances in the ap-south-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ca_central_1: {
            name: 'Disapproved Instance Types Region: ca-central-1',
            description: 'Checks for unapproved instances in the ca-central-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            disapproved_instance_types_global: settings.disapproved_instance_types_global || this.settings.disapproved_instance_types_global.default,
            disapproved_instance_types_region_us_east_1: settings.disapproved_instance_types_region_us_east_1 || this.settings.disapproved_instance_types_region_us_east_1.default,
            disapproved_instance_types_region_us_east_2: settings.disapproved_instance_types_region_us_east_2 || this.settings.disapproved_instance_types_region_us_east_2.default,
            disapproved_instance_types_region_us_west_1: settings.disapproved_instance_types_region_us_west_1 || this.settings.disapproved_instance_types_region_us_west_1.default,
            disapproved_instance_types_region_us_west_2: settings.disapproved_instance_types_region_us_west_2 || this.settings.disapproved_instance_types_region_us_west_2.default,
            disapproved_instance_types_region_ap_northeast_1: settings.disapproved_instance_types_region_ap_northeast_1 || this.settings.disapproved_instance_types_region_ap_northeast_1.default,
            disapproved_instance_types_region_ap_northeast_2: settings.disapproved_instance_types_region_ap_northeast_2 || this.settings.disapproved_instance_types_region_ap_northeast_2.default,
            disapproved_instance_types_region_ap_southeast_1: settings.disapproved_instance_types_region_ap_southeast_1 || this.settings.disapproved_instance_types_region_ap_southeast_1.default,
            disapproved_instance_types_region_ap_southeast_2: settings.disapproved_instance_types_region_ap_southeast_2 || this.settings.disapproved_instance_types_region_ap_southeast_2.default,
            disapproved_instance_types_region_eu_central_1: settings.disapproved_instance_types_region_eu_central_1 || this.settings.disapproved_instance_types_region_eu_central_1.default,
            disapproved_instance_types_region_eu_west_1: settings.disapproved_instance_types_region_eu_west_1 || this.settings.disapproved_instance_types_region_eu_west_1.default,
            disapproved_instance_types_region_eu_west_2: settings.disapproved_instance_types_region_eu_west_2 || this.settings.disapproved_instance_types_region_eu_west_2.default,
            disapproved_instance_types_region_eu_west_3: settings.disapproved_instance_types_region_eu_west_3 || this.settings.disapproved_instance_types_region_eu_west_3.default,
            disapproved_instance_types_region_sa_east_1: settings.disapproved_instance_types_region_sa_east_1 || this.settings.disapproved_instance_types_region_sa_east_1.default,
            disapproved_instance_types_region_ap_south_1: settings.disapproved_instance_types_region_ap_south_1 || this.settings.disapproved_instance_types_region_ap_south_1.default,
            disapproved_instance_types_region_ca_central_1: settings.disapproved_instance_types_region_ca_central_1 || this.settings.disapproved_instance_types_region_ca_central_1.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var instancesFound = [];
        var instanceCountGlobal = 0;
        var globalSetting = config.disapproved_instance_types_global.split(",");
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.ec2, function(region, rcb){

            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No disapproved instances found', region);
                return rcb();
            }

            var instanceCount = 0;
            var regionUnderscore = region.replace(/-/g, '_');
            var regionSetting = config['disapproved_instance_types_region_'+regionUnderscore].split(",");

            for (i in describeInstances.data) {
                for (j in describeInstances.data[i].Instances) {
                    var instance = describeInstances.data[i].Instances[j];
                    var disapprovedTypeRegion = (regionSetting.indexOf(instance.InstanceType) > -1 ? true : false);
                    var disapprovedTypeGlobal = (globalSetting.indexOf(instance.InstanceType) > -1 ? true : false);

                    if (disapprovedTypeRegion || disapprovedTypeGlobal){
                        if (instancesFound.length>0) {
                            var instanceWithType = instancesFound.findIndex(obj => obj.instanceType == instance.InstanceType);
                        } else {
                            instanceWithType = -1;
                        }

                        if (instanceWithType<0) {
                            instancesFound.push({instanceType:instance.InstanceType,region:region,state:instance.State.Name,count:0,disapprovedRegion:disapprovedTypeRegion,disapprovedGlobally:disapprovedTypeGlobal});
                            var instanceWithType = instancesFound.findIndex(obj => obj.instanceType == instance.InstanceType);

                            instancesFound[instanceWithType].count +=1;

                            if (instancesFound[instanceWithType].disapprovedGlobally) {
                                instanceCountGlobal += 1;
                            }

                            if (instancesFound[instanceWithType].disapprovedRegion) {
                                instanceCount += 1;
                            }
                        }
                    }
                }
            }

            // Print region results
            if (!regionSetting) {
                helpers.addResult(results, 3,
                    'The region: ' + region + ' does not have disapproved instances type settings.', region);
            } else if (instancesFound.length>0) {
                var instancesNotApproved = instancesFound.filter(obj => {
                        return obj.disapprovedRegion == true
                    });
                for (i in instancesNotApproved){
                    helpers.addResult(results, 2,
                        instancesNotApproved[i].count + ' disapproved EC2 ' + instancesNotApproved[i].instanceType + ' instances launched in ' +
                        region + ' region', region, null, custom);
                }
            }

            rcb();
        });

        // Print global results
        if (!globalSetting) {
            helpers.addResult(results, 3,
                'There is not a global approved instances type setting.', region);
        } else if (instancesFound.length>0) {
            var instancesNotApproved = instancesFound.filter(obj => {
                    return obj.disapprovedGlobally == true
                });
            for (i in instancesNotApproved){
                helpers.addResult(results, 2,
                    instancesNotApproved[i].count + ' globally disapproved EC2 ' + instancesNotApproved[i].instanceType + ' instances launched in ' +
                    instancesNotApproved[i].region + ' region', null, null, custom);
            }
        }

        callback(null, results, source);
    }
};
