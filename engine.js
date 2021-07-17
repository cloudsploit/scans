var async = require('async');
var os = require('os');
var exports = require('./exports.js');
var opaExports = require('./opa_exports');
var suppress = require('./postprocess/suppress.js');
var output = require('./postprocess/output.js');
var opaHelper = require('./helpers/opa/opaInstaller');
var opaPolicyEval = require('./helpers/opa/opaPolicyExecutor');
var fs = require('fs');

var collectionFile = './collection.json';
var azureHelper = require('./helpers/azure/auth.js');

function runAuth(settings, remediateConfig, callback) {
    if (settings.cloud && settings.cloud == 'azure') {
        azureHelper.login(remediateConfig, function(err, loginData) {
            if (err) return (callback(err));
            remediateConfig.token = loginData.token;
            return callback();
        });
    } else callback();
}
 /**
 * The main function to execute CloudSploit scans.
 * @param cloudConfig The configuration for the cloud provider.
 * @param settings General purpose settings.
 */
var engine = function(cloudConfig, settings) {
    // Initialize any suppression rules based on the the command line arguments
    var suppressionFilter = suppress.create(settings.suppress);

    // Initialize the output handler
    var outputHandler = output.create(settings);

    // Configure Service Provider Collector
    var collector = require(`./collectors/${settings.cloud}/collector.js`);
    var plugins = exports[settings.cloud];
    var apiCalls = [];
    if (settings.opa) {
        plugins = opaExports[settings.cloud];
        var osType = os.type();
        var opaPath;
        if ( osType === 'Windows_NT') {
            opaPath = 'opa.exe';
        }
        else {
            opaPath = 'opa';
        }
    }

    // Load resource mappings
    var resourceMap;
    try {
        resourceMap = require(`./helpers/${settings.cloud}/resources.js`);
        // var fsData = fs.readFileSync('./plugins/aws/sqs/sqsEncrypted2.rego', 'utf8');
        // var meta = fsData.toString().split('#-');
        // meta = meta[0].split(':=');
        // var meta1 = meta[1];
        // var metaData = JSON.parse(meta1.toString());

    } catch (e) {
        resourceMap = {};
    }

    // Print customization options
    if (settings.compliance) console.log(`INFO: Using compliance modes: ${settings.compliance.join(', ')}`);
    if (settings.govcloud) console.log('INFO: Using AWS GovCloud mode');
    if (settings.china) console.log('INFO: Using AWS China mode');
    if (settings.ignore_ok) console.log('INFO: Ignoring passing results');
    if (settings.skip_paginate) console.log('INFO: Skipping AWS pagination mode');
    if (settings.suppress && settings.suppress.length) console.log('INFO: Suppressing results based on suppress flags');
    if (settings.remediate && settings.remediate.length) console.log('INFO: Remediate the plugins mentioned here');
    if (settings.plugin) {
        if (!plugins[settings.plugin]) return console.log(`ERROR: Invalid plugin: ${settings.plugin}`);
        console.log(`INFO: Testing plugin: ${plugins[settings.plugin].title}`);
    }

    // STEP 1 - Obtain API calls to make
    console.log('INFO: Determining API calls to make...');

    var skippedPlugins = [];
    var opaPlugins = {};
    Object.entries(plugins).forEach(function(p){
        var pluginId = p[0];
        var plugin = p[1];
        if (settings.opa) {
            // creating new plugins list to loop over later with the metadata
            var pluginFileData = fs.readFileSync(plugin, 'utf8');
            opaPlugins[pluginId] = opaHelper.getMetaData(pluginFileData);
            opaPlugins[pluginId].path = plugin;
            // we need to have the metadata here also to get the plugin.apis
            plugin = opaPlugins[pluginId];
        }
        // Skip plugins that don't match the ID flag
        var skip = false;
        if (settings.plugin && settings.plugin !== pluginId) {
            skip = true;
        } else {
            // Skip GitHub plugins that do not match the run type
            if (settings.cloud == 'github') {
                if (cloudConfig.organization &&
                    plugin.types.indexOf('org') === -1) {
                    skip = true;
                    console.debug(`DEBUG: Skipping GitHub plugin ${plugin.title} because it is not for Organization accounts`);
                } else if (!cloudConfig.organization &&
                    plugin.types.indexOf('org') === -1) {
                    skip = true;
                    console.debug(`DEBUG: Skipping GitHub plugin ${plugin.title} because it is not for User accounts`);
                }
            }

            if (settings.compliance && settings.compliance.length) {
                if (!plugin.compliance || !Object.keys(plugin.compliance).length) {
                    skip = true;
                    console.debug(`DEBUG: Skipping plugin ${plugin.title} because it is not used for compliance programs`);
                } else {
                    // Compare
                    var cMatch = false;
                    settings.compliance.forEach(function(c){
                        if (plugin.compliance[c]) cMatch = true;
                    });
                    if (!cMatch) {
                        skip = true;
                        console.debug(`DEBUG: Skipping plugin ${plugin.title} because it did not match compliance programs ${settings.compliance.join(', ')}`);
                    }
                }
            }
        }

        if (skip) {
            skippedPlugins.push(pluginId);
        } else {
            plugin.apis.forEach(function(api) {
                if (apiCalls.indexOf(api) === -1) apiCalls.push(api);
            });
            // add the remediation api calls also for data to be collected
            if (settings.remediate && settings.remediate.includes(pluginId)){
                plugin.apis_remediate.forEach(function(api) {
                    if (apiCalls.indexOf(api) === -1) apiCalls.push(api);
                });
            }
        }
    });

    if (!apiCalls.length) return console.log('ERROR: Nothing to collect.');

    console.log(`INFO: Found ${apiCalls.length} API calls to make for ${settings.cloud} plugins`);
    console.log('INFO: Collecting metadata. This may take several minutes...');

    const initializeFile = function(file, type, testQuery, resource) {
        if (!file['access']) file['access'] = {};
        if (!file['pre_remediate']) file['pre_remediate'] = {};
        if (!file['pre_remediate']['actions']) file['pre_remediate']['actions'] = {};
        if (!file['pre_remediate']['actions'][testQuery]) file['pre_remediate']['actions'][testQuery] = {};
        if (!file['pre_remediate']['actions'][testQuery][resource]) file['pre_remediate']['actions'][testQuery][resource] = {};
        if (!file['post_remediate']) file['post_remediate'] = {};
        if (!file['post_remediate']['actions']) file['post_remediate']['actions'] = {};
        if (!file['post_remediate']['actions'][testQuery]) file['post_remediate']['actions'][testQuery] = {};
        if (!file['post_remediate']['actions'][testQuery][resource]) file['post_remediate']['actions'][testQuery][resource] = {};
        if (!file['remediate']) file['remediate'] = {};
        if (!file['remediate']['actions']) file['remediate']['actions'] = {};
        if (!file['remediate']['actions'][testQuery]) file['remediate']['actions'][testQuery] = {};
        if (!file['remediate']['actions'][testQuery][resource]) file['remediate']['actions'][testQuery][resource] = {};

        return file;
    };

    // STEP 2 - Collect API Metadata from Service Providers
    collector(cloudConfig, {
        api_calls: apiCalls,
        paginate: settings.skip_paginate,
        govcloud: settings.govcloud,
        china: settings.china
    }, function(err, collection) {
        if (err || !collection || !Object.keys(collection).length) return console.log(`ERROR: Unable to obtain API metadata: ${err || 'No data returned'}`);
        outputHandler.writeCollection(collection, settings.cloud);

        console.log('INFO: Metadata collection complete. Analyzing...');
        console.log('INFO: Analysis complete. Scan report to follow...');

        var maximumStatus = 0;

        
        function executePlugins(cloudRemediateConfig) {
            if (settings.opa) {
                // check if old collection is present,if so delete it
                if (fs.existsSync(collectionFile)) {
                    fs.unlinkSync(collectionFile);
                }
                // write the collection
                fs.writeFileSync(collectionFile, JSON.stringify(collection, null, 4));
            }
            if (settings.opa) plugins = opaPlugins;

            async.mapValuesLimit(plugins, 10, function (plugin, key, pluginDone) {
                if (skippedPlugins.indexOf(key) > -1) return pluginDone(null, 0);

                var postRun = function (err, results) {
                    if (err) return console.log(`ERROR: ${err}`);
                    if (!results || !results.length) {
                        console.log(`Plugin ${plugin.title} returned no results. There may be a problem with this plugin.`);
                    } else {
                        for (var r in results) {
                            // If we have suppressed this result, then don't process it
                            // so that it doesn't affect the return code.
                            if (suppressionFilter([key, results[r].region || 'any', results[r].resource || 'any'].join(':'))) {
                                continue;
                            }

                            var complianceMsg = [];
                            if (settings.compliance && settings.compliance.length) {
                                settings.compliance.forEach(function (c) {
                                    if (plugin.compliance && plugin.compliance[c]) {
                                        complianceMsg.push(`${c.toUpperCase()}: ${plugin.compliance[c]}`);
                                    }
                                });
                            }
                            complianceMsg = complianceMsg.join('; ');
                            if (!complianceMsg.length) complianceMsg = null;

                            // Write out the result (to console or elsewhere)
                            outputHandler.writeResult(results[r], plugin, key, complianceMsg);

                            // Add this to our tracking for the worst status to calculate
                            // the exit code
                            maximumStatus = Math.max(maximumStatus, results[r].status);
                            // Remediation
                            if (settings.remediate && settings.remediate.length) {
                                if (settings.remediate.indexOf(key) > -1) {
                                    if (results[r].status === 2) {
                                        var resource = results[r].resource;
                                        var event = {};
                                        event.region = results[r].region;
                                        event['remediation_file'] = {};
                                        event['remediation_file'] = initializeFile(event['remediation_file'], 'execute', key, resource);
                                        plugin.remediate(cloudRemediateConfig, collection, event, resource, (err, result) => {
                                            if (err) return console.log(err);
                                            return console.log(result);
                                        });
                                    }
                                }
                            }
                        }

                    }
                    setTimeout(function () {
                        pluginDone(err, maximumStatus);
                    }, 0);
                };

                if (plugin.asl) {
                    console.log(`INFO: Using custom ASL for plugin: ${plugin.title}`);
                    // Inject APIs and resource maps
                    plugin.asl.apis = plugin.apis;
                    var aslConfig = require('./helpers/asl/config.json');
                    var aslVersion = plugin.asl.version ? plugin.asl.version : aslConfig.current_version;
                    let aslRunner;
                    try {
                        aslRunner = require(`./helpers/asl/asl-${aslVersion}.js`);

                    } catch (e) {
                        postRun('Error: ASL: Wrong ASL Version: ', e);
                    }

                    aslRunner(collection, plugin.asl, resourceMap, postRun);
                } else if (settings.opa) {
                    opaHelper.downloadOPAforOs((err) => {
                        if (err) {
                            return console.log(err);
                        }
                        //opaPolicyEval.opaEval(plugin.path, collectionFile, opaPath, plugin, resourceMap, postRun
                        opaPolicyEval.opaRunner(collection, opaPath, plugin, resourceMap, postRun);
                        // (err, results) => {
                        //     if (err) {
                        //         return console.log(err);
                        //     }
                        //     // Write out the result (to console or elsewhere)
                        //     var complianceMsg = [];
                        //     for (var r in results) {
                        //         outputHandler.writeResult(results[r], plugin, key, complianceMsg);
                        //         maximumStatus = Math.max(maximumStatus, results[r].status);
                        //     }
                        //     setTimeout(function () {
                        //         pluginDone(err, maximumStatus);
                        //     }, 0);
                        // }
                        //);
                    });
                } else {
                    plugin.run(collection, settings, postRun);
                }
            }, function (err) {
                if (err) return console.log(err);
                // console.log(JSON.stringify(collection, null, 2));
                outputHandler.close();
                if (settings.exit_code) {
                    // The original cloudsploit always has a 0 exit code. With this option, we can have
                    // the exit code depend on the results (useful for integration with CI systems)
                    console.log(`INFO: Exiting with exit code: ${maximumStatus}`);
                    process.exitCode = maximumStatus;
                }
                // check if  collection is present,if so delete it
                if (fs.existsSync(collectionFile)) {
                    fs.unlinkSync(collectionFile);
                }
                console.log('INFO: Scan complete');
            });
        }

        if (settings.remediate && settings.remediate.length && cloudConfig.remediate) {
            runAuth(settings, cloudConfig.remediate, function (err) {
                if (err) return console.log(err);
                executePlugins(cloudConfig.remediate);
            });
        } else {
            executePlugins(cloudConfig);
        }
    });
};

module.exports = engine;
