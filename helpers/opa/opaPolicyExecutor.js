// Executes the policy
var opahelpers = require('./opaInstaller');
var helpers = require('../aws');
var async = require('async');
var fs = require('fs');

var parse = function(obj, path) {
    if (typeof path == 'string') path = path.split('.');
    if (Array.isArray(path) && path.length) {
        var localPath = path.shift();
        if (obj[localPath] || typeof obj[localPath] === 'boolean') {
            return parse(obj[localPath], path);
        } else {
            return 'not set';
        }
    } else {
        return obj;
    }
};


// data: path for the rego file. we can later improve it to have multiple data files or bundle which will include
//      data and input togather
// input: input in a json format.
var opaEval = (data, input, opaPath, rules, callback) => {
    var results ={};

    async.eachOf(rules, function(rule, ruleName, cb) {
        var command = `${opaPath} eval -i ${input} -d ${data} "${rule}"`;
        opahelpers.executeCommand(command, {shell: true}, (err, stdoutbuf) => {
            if (err) {
                return cb(err);
            }
            var result = JSON.parse(stdoutbuf);
            results[ruleName] = result.result[0].expressions[0].value;
            cb();
        });
    }, function(err) {
        if (err) {
            console.log(err);
            return callback(err);
        }
        var finalresults = [];
        for ( var res in results ){
            var caseResult = results[res];
            caseResult.forEach(resultItem => {
                var resource = resultItem.arn;
                var region = resultItem.region;
                var newMassage = resultItem.msg;
                var status = resultItem.status;
                helpers.addResult(finalresults, parseInt(status),
                    newMassage,
                    region, resource);
            });
        }
        return callback(finalresults);
    });
};

var opaEvalSingle = (data, collectionFile, opaPath, rules, callback) => {
    var results ={};
    // check if old collection is present,if so delete it

    async.eachOf(rules, function(rule, ruleName, cb) {
        var command = `${opaPath} eval -i ${collectionFile} -d ${data} "${rule}"`;
        opahelpers.executeCommand(command, {shell: true}, (err, stdoutbuf) => {
            if (err) {
                return cb(err);
            }
            var result = JSON.parse(stdoutbuf);
            results[ruleName] = result.result[0].expressions[0].value;
            cb();
        });
    }, function(err) {
        if (err) {
            console.log(err);
            return callback(err);
        }
        var finalresults = [];
        for ( var res in results ){
            var resultItem = results[res];
            //var resource = resultItem.arn;
            //var region = resultItem.region;
            if (resultItem &&
                resultItem.length &&
                resultItem[0]){
                var newMassage = resultItem[0].msg;
                var status = resultItem[0].status;
                finalresults.push({
                    message: newMassage,
                    status: status
                });
            }
        }

        if( fs.existsSync(collectionFile) && finalresults.length){
            fs.unlinkSync(collectionFile);
        }
        return callback(null, finalresults);
    });
};

var opaRunner = function(source, opaPath, plugin, resourceMap, callback) {
    if (!source) return callback('No source or input provided');
    if (!opaPath) return callback('No opa executable provided');
    if (!plugin) return callback('No plugin provided for input');
    var service = plugin.category.toLowerCase();
    var api = plugin.apis[0].split(':')[1];
    var resourcePath;

    if (resourceMap &&
        resourceMap[service] &&
        resourceMap[service][api]) {
        resourcePath = resourceMap[service][api];
    }

    // Split apis into service:api
    // TODO: support conditions that use different APIs

    if (!source[service]) return callback(`Source data did not contain service: ${service}`);
    if (!source[service][api]) return callback(`Source data did not contain API: ${api}`);

    var results = [];
// rCb function
    var sourceCol = source[service][api];
    async.eachOfLimit(sourceCol, 5, function(regionVal, region,rcb){
        if (typeof regionVal !== 'object') rcb();
        if (regionVal.err) {
            results.push({
                status: 3,
                message: regionVal.err.message || 'Error',
                region: region
            });
            rcb();
        } else if (regionVal.data && regionVal.data.length) {
            // It's an array, loop
            regionVal.data.forEach(function(regionData) {
                var validated = evaluateConditions(regionData, input.conditions);
                var parsedResource = parse(regionData, resourcePath);
                if (typeof parsedResource !== 'string') parsedResource = null;

                results.push({
                    status: validated.status,
                    resource: parsedResource,
                    message: validated.message,
                    region: region
                });
            });
        } else {
            async.eachOfLimit(regionVal, 10, function(resourceObj, resourceName,rNcb){
                if (resourceObj.err) {
                results.push({
                    status: 3,
                    resource: resourceName,
                    message: resourceObj.err.message || 'Error',
                    region: region
                });
                rNcb();
            } else if (!resourceObj.data) {
                results.push({
                    status: 3,
                    resource: resourceName,
                    message: 'No data returned',
                    region: region
                });
                rNcb();
            } else {
                var parsedResource = parse(resourceObj.data, resourcePath);
                if (typeof parsedResource !== 'string') parsedResource = null;
                if (resourceName.indexOf('https') !== -1){
                    resourceName = resourceName.split('/');
                    resourceName = resourceName[resourceName.length-1];
                }
                var collectionFile = './single_'+region+'_'+resourceName+'.json';
                if( fs.existsSync(collectionFile)){
                    fs.unlinkSync(collectionFile);
                }
                // write the collection
                fs.writeFileSync(collectionFile, JSON.stringify(resourceObj, null, 4));
                opaEvalSingle(plugin.path, collectionFile, opaPath, plugin.rules, function (err, finalResults){
                    if (err) {
                        return rNcb(err);
                    }
                    if (!finalResults || !finalResults.length){
                        results.push({
                            status: 2/*3*/,
                            resource: resourceName,
                            message: 'Resource property did not match the condition'/*'No data returned'*/,
                            region: region
                        });
                        return rNcb();
                    }
                    finalResults.forEach(resultElement => {
                        results.push({
                            status: resultElement.status,
                            resource: parsedResource ? parsedResource : resourceName,
                            message: resultElement.message,
                            region: region
                        });
                    });
                    rNcb();
                });
            }},function(err){
                if(err) rcb(err);
                else rcb();
            });
        }
    },function (err){
        if (err){
            return callback(err);
        }
        callback(null, results, source[service][api]);
    });

};

module.exports = {
    opaEval: opaEval,
    opaRunner: opaRunner
};
// ./opa eval -i input.json -d example.rego "data.example.violation[x]"