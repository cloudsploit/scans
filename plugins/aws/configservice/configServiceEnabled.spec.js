var expect = require('chai').expect;
const configServiceEnabled = require('./configServiceEnabled');

const describeConfigurationRecorders = [
    {
        "name": "default",
        "roleARN": "arn:aws:iam::111111111111:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        "recordingGroup": {
            "allSupported": true,
            "includeGlobalResourceTypes": true,
            "resourceTypes": []
        }
    },
    {   // global service monitoring disabled
        "name": "default",
        "roleARN": "arn:aws:iam::111111111111:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        "recordingGroup": {
            "allSupported": true,
            "includeGlobalResourceTypes": false,
            "resourceTypes": []
        }
    }
]

const describeConfigurationRecorderStatus =[
    {
        "name": "default",
        "lastStartTime": "2021-01-13T22:49:49.468Z",
        "lastStopTime": "2021-01-14T03:42:24.188Z",
        "recording": true,
        "lastStatus": "SUCCESS",
        "lastStatusChangeTime": "2021-01-14T02:50:03.295Z"
    },
    {   // recorders configured but not recording
        "name": "default",
        "lastStartTime": "2021-01-13T22:49:49.468Z",
        "lastStopTime": "2021-01-14T03:42:24.188Z",
        "recording": false,
        "lastStatus": "SUCCESS",
        "lastStatusChangeTime": "2021-01-14T02:50:03.295Z"
    },
    {   // configured recorders have not delivered till now
        "name": "default",
        "lastStartTime": "2021-01-13T22:49:49.468Z",
        "lastStopTime": "2021-01-14T03:42:24.188Z",
        "recording": true,
        "lastStatus": "",
        "lastStatusChangeTime": "2021-01-14T02:50:03.295Z"
    },
    {   // configured recorders does not have last status property
        "name": "default",
        "lastStartTime": "2021-01-13T22:49:49.468Z",
        "lastStopTime": "2021-01-14T03:42:24.188Z",
        "recording": true,
        "lastStatusChangeTime": "2021-01-14T02:50:03.295Z"
    }
]

const createCache = (recorders, recordersStatus) => {
    const records = (recorders && recorders.length) ? recorders: null;
    const recordStatus = (recordersStatus && recordersStatus.length) ? recordersStatus: null;
    return {
        configservice: {
            describeConfigurationRecorders: {
                'us-east-1': {
                    data: records
                },
            },
            describeConfigurationRecorderStatus: {
                'us-east-1': {
                        data: recordStatus
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        configservice: {
            describeConfigurationRecorders: {
                'us-east-1': {
                    err: {
                        message: 'error while getting recorders'
                    },
                },
            },
            describeConfigurationRecorderStatus: {
                'us-east-1': {
                    err: {
                        message: 'error while getting recorder status'
                    },
                },
            },
        },
    };
};

const createRecorderStatusErrorCache = (recorders) => {
    return {
        configservice: {
            describeConfigurationRecorders: {
                'us-east-1': {
                    data: recorders
                },
            },
            describeConfigurationRecorderStatus: {
                'us-east-1': {
                    err: {
                        message: 'error while getting recorder status'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        configservice: {
            describeConfigurationRecorders: {
                'us-east-1': null,
            },
            describeConfigurationRecorderStatus: {
                'us-east-1': null,
            },
        }
    }
};

describe('configServiceEnabled', () => {
    describe('run', () => {
        
        it('should PASS if configuration recorders are recording and delivering', (done) => {
            const cache = createCache([describeConfigurationRecorders[0]], [describeConfigurationRecorderStatus[0]]);
            configServiceEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if configuration recorders are monitoring global services', (done) => {
            const cache = createCache([describeConfigurationRecorders[0]], [describeConfigurationRecorderStatus[0]]);
            configServiceEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if configuration recorders are not monitoring global services', (done) => {
            const cache = createCache([describeConfigurationRecorders[1]], [describeConfigurationRecorderStatus[0]]);
            configServiceEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });
        it('should FAIL if configuration recorders does not have last status property', (done) => {
            const cache = createCache([describeConfigurationRecorders[0]], [describeConfigurationRecorderStatus[3]]);
            configServiceEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(1);
                done();
            });
        });
        it('should FAIL if configuration recorders have not delivered', (done) => {
            const cache = createCache([describeConfigurationRecorders[0]], [describeConfigurationRecorderStatus[2]]);
            configServiceEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if configuration recorders are not recording', (done) => {
            const cache = createCache([describeConfigurationRecorders[0]], [describeConfigurationRecorderStatus[1]]);
            configServiceEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if configuration recorders are not found', (done) => {
            const cache = createNullCache();
            configServiceEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to get configuration recorders', function (done) {
            const cache = createErrorCache();
            configServiceEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to get configuration recorder status', (done) => {
            const cache = createRecorderStatusErrorCache([describeConfigurationRecorders[0]]);
            configServiceEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
    })

})
