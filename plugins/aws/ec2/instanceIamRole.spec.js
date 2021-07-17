var expect = require('chai').expect;
const instanceIamRole = require('./instanceIamRole');

const describeInstances = [
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462547",
                "InstanceType": "t2.micro",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111122223333:instance-profile/aws-elasticbeanstalk-ec2-role",
                    "Id": "AIPAYE32SRU5VWPEXDHQE"
                },
            },
        ],
    },
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462547",
                "InstanceType": "t2.micro",
            },
        ],
    },
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462547",
                "InstanceType": "t2.micro",
                "State": {
                    "Name": "shutting-down"
                },
            },
        ],
    },
];

const createCache = (instances) => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': null,
            },
        },
    };
};


describe('instanceIamRole', function () {
    describe('run', function () {
        it('should PASS if all instances are using IAM roles', function (done) {
            const cache = createCache([describeInstances[0]]);
            instanceIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if instance does not use an IAM role', function (done) {
            const cache = createCache([describeInstances[1]]);
            instanceIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if instance does not use an IAM role, but is shutting-down', function (done) {
            const cache = createCache([describeInstances[1]]);
            instanceIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if instance does not use an IAM role, but is shutting-down', function (done) {
            const cache = createCache([describeInstances[2]]);
            instanceIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if more than threshold instances do not use an IAM role', function (done) {
            const cache = createCache([describeInstances[1], describeInstances[1], describeInstances[1]]);
            var settings = {
                instance_iam_role_threshold: 2
            };
            instanceIamRole.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no instances found', function (done) {
            const cache = createCache([]);
            instanceIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe instances', function (done) {
            const cache = createErrorCache();
            instanceIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe instances response not found', function (done) {
            const cache = createNullCache();
            instanceIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
        
    });
});
