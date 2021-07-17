var request = require('request');
var locations = require(__dirname + '/locations.js');

var dontReplace = {
    'type': {
        'roleDefinitions': 'roleType'
    }
};

// Recursive function that converts API response containing "properties"
// into single unified response with properties at top-level.
// This matches the format of the now-replaced SDK.
function reduceProperties(service, collection) {
    if (Array.isArray(collection)) {
        collection.forEach(function(col) {
            reduceProperties(service, col);
        });
    } else if (typeof collection == 'object') {
        if (collection.properties && typeof collection.properties == 'object') {
            for (var p in collection.properties) {
                if (dontReplace[p] && dontReplace[p][service]) {
                    collection[dontReplace[p][service]] = collection.properties[p];
                } else {
                    collection[p] = collection.properties[p];
                }
            }
            delete collection.properties;
        }
    }
}

module.exports = {
    login: function(azureConfig, callback) {
        if (!azureConfig.ApplicationID) return callback('No ApplicationID provided');
        if (!azureConfig.KeyValue) return callback('No KeyValue provided');
        if (!azureConfig.DirectoryID) return callback('No DirectoryID provided');
        if (!azureConfig.SubscriptionID) return callback('No SubscriptionID provided');

        var msRestAzure = require('ms-rest-azure');

        function performLogin(tokenAudience, cb) {
            msRestAzure.loginWithServicePrincipalSecret(
                azureConfig.ApplicationID,
                azureConfig.KeyValue,
                azureConfig.DirectoryID,
                tokenAudience, function(err, credentials) {
                    if (err) return cb(err);
                    if (!credentials) return cb('Unable to log into Azure using provided credentials.');
                    if (!credentials.environment) return cb('Unable to obtain environment from Azure application');
                    if (!credentials.tokenCache ||
                        !credentials.tokenCache._entries ||
                        !credentials.tokenCache._entries[0] ||
                        !credentials.tokenCache._entries[0].accessToken) {
                        return cb('Unable to obtain token from Azure.');
                    }

                    cb(null, credentials);
                });
        }

        // First, login without audience
        performLogin(null, function(err, credentials) {
            if (err) return callback(err);
            performLogin({ tokenAudience: 'graph' }, function(graphErr, graphCredentials) {
                if (graphErr) return callback(graphErr);
                performLogin({ tokenAudience: 'https://vault.azure.net' }, function(vaultErr, vaultCredentials) {
                    if (vaultErr) return callback(vaultErr);
                    callback(null, {
                        environment: credentials.environment,
                        token: credentials.tokenCache._entries[0].accessToken,
                        graphToken: graphCredentials.tokenCache._entries[0].accessToken,
                        vaultToken: vaultCredentials.tokenCache._entries[0].accessToken
                    });
                });
            });
        });
    },

    call: function(params, callback) {
        var headers = {
            'Authorization': `Bearer ${params.token}`
        };

        if (params.body && Object.keys(params.body).length) {
            headers['Content-Length'] = JSON.stringify(params.body).length;
            headers['Content-Type'] = 'application/json;charset=UTF-8';
        }

        request({
            method: params.method ? params.method : params.post ? 'POST' : 'GET',
            uri: params.url,
            headers: headers,
            body: params.body ? JSON.stringify(params.body) : null
        }, function(error, response, body) {
            if (response && [200, 202].includes(response.statusCode) && body) {
                try {
                    body = JSON.parse(body);
                } catch (e) {
                    return callback(`Error parsing response from Azure API: ${e}`);
                }
                return callback(null, body);
            } else {
                if (body) {
                    try {
                        body = JSON.parse(body);
                    } catch (e) {
                        return callback(`Error parsing error response from Azure API: ${e}`);
                    }

                    if (typeof body == 'string') {
                        // Need to double parse it
                        try {
                            body = JSON.parse(body);
                        } catch (e) {
                            return callback(`Error parsing error response string from Azure API: ${e}`);
                        }
                    }

                    if (body &&
                        body.error &&
                        body.error.message &&
                        typeof body.error.message == 'string') {
                        return callback(body.error.message);
                    } else if (body &&
                        body['odata.error'] &&
                        body['odata.error'].message &&
                        body['odata.error'].message.value &&
                        typeof body['odata.error'].message.value == 'string') {
                        if (body['odata.error'].requestId) {
                            body['odata.error'].message.value += ` RequestId: ${body['odata.error'].requestId}`;
                        }
                        return callback(body['odata.error'].message.value);
                    } else if (body &&
                        body.message &&
                        typeof body.message == 'string') {
                        if (body.code && typeof body.code == 'string') {
                            body.message = (body.code + ': ' + body.message);
                        }
                        return callback(body.message);
                    }

                    // console.log(`[ERROR] Unhandled error from Azure API: Body: ${JSON.stringify(body)}`);
                }

                // console.log(`[ERROR] Unhandled error from Azure API: Error: ${error}`);
                return callback(`Unknown error occurred while calling the Azure API: ERROR (${JSON.stringify(body.Message)})`);
            }
        });
    },

    addLocations: function(obj, service, collection, err, data) {
        if (!service || !locations[service]) return;
        locations[service].forEach(function(location) {
            collection[location.toLowerCase()] = {};
            if (err) {
                collection[location.toLowerCase()].err = err;
            } else if (data) {
                if (data.value && Array.isArray(data.value)) {
                    collection[location.toLowerCase()].data = data.value.filter(function(dv) {
                        if (dv.location &&
                            dv.location.toLowerCase().replace(/ /g, '') == location.toLowerCase()) {
                            return true;
                        } else if (location.toLowerCase() == 'global' && (!dv.location || obj.ignoreLocation)) {
                            return true;
                        }
                        return false;
                    });
                    reduceProperties(service, collection[location.toLowerCase()].data);
                }
            }
        });
    },

    reduceProperties: reduceProperties
};