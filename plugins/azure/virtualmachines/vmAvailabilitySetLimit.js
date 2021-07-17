var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Availability Set Limit',
    category: 'Virtual Machines',
    description: 'Determine if the number of VM instances is close to the Azure per-availability set limit',
    more_info: 'Azure limits availability sets to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/overview',
    recommended_action: 'Contact Azure support to increase the number of instances available',
    apis: ['resourceGroups:list', 'availabilitySets:listByResourceGroup'],
    settings: {
        instance_limit_percentage_fail: {
            name: 'Instance Limit Percentage Fail',
            description: 'Return a failing result when utilized instances equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 90
        },
        instance_limit_percentage_warn: {
            name: 'Instance Limit Percentage Warn',
            description: 'Return a warning result when utilized instances equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 75
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            instance_limit_percentage_fail: settings.instance_limit_percentage_fail || 
                this.settings.instance_limit_percentage_fail.default,
            instance_limit_percentage_warn: settings.instance_limit_percentage_warn || 
                this.settings.instance_limit_percentage_warn.default
        };

        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.resourceGroups, function(location, rcb){
            var resourceGroups = helpers.addSource(cache, source, 
                ['resourceGroups', 'list', location]);

            if (!resourceGroups) return rcb();

            if (resourceGroups.err || !resourceGroups.data) {
                helpers.addResult(results, 3, 
                    'Unable to query Resource Groups: ' + helpers.addError(resourceGroups), location);
                return rcb();
            }

            if (!resourceGroups.data.length) {
                helpers.addResult(results, 0, 'No existing Resource Groups', location);
                return rcb();
            }

            async.each(resourceGroups.data, function(resourceGroup, scb){
                var availabilitySets = helpers.addSource(cache, source, 
                    ['availabilitySets', 'listByResourceGroup', location, resourceGroup.id]);

                if (!availabilitySets || availabilitySets.err || !availabilitySets.data) {
                    helpers.addResult(results, 3, 
                        'Unable to query Availability Sets: ' + helpers.addError(availabilitySets), location);
                    return scb();
                }

                if (!availabilitySets.data.length) {
                    helpers.addResult(results, 0, 'No existing Availability Sets', location);
                    return scb();
                }

                var limits = {
                    'max-instances': 200
                };

                availabilitySets.data.forEach(availabilitySet => {
                    if (availabilitySet.virtualMachines) {
                        var vmInstances = availabilitySet.virtualMachines.length;
                    } else {
                        return;
                    }

                    var percentage = Math.ceil((vmInstances / limits['max-instances']) * 100);
                    var returnMsg = 'Availability Set contains ' + vmInstances + ' of ' +
                        limits['max-instances'] + ' (' + percentage + '%) available instances';

                    if (percentage >= config.instance_limit_percentage_fail) {
                        helpers.addResult(results, 2, returnMsg, location, availabilitySet.id);
                    } else if (percentage >= config.instance_limit_percentage_warn) {
                        helpers.addResult(results, 1, returnMsg, location, availabilitySet.id);
                    } else {
                        helpers.addResult(results, 0, returnMsg, location, availabilitySet.id);
                    }
                });

                scb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};