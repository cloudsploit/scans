var expect = require('chai').expect;
var iamUserInUse = require('./iamUserInUse')


const currentDate = new Date();
const dayOldDate = new Date();
dayOldDate.setDate(dayOldDate.getDate()-1);
const oldDate = new Date();
oldDate.setFullYear(oldDate.getFullYear()-1);

const users = [
    {
        "user": "<root_account>",
        "arn": "arn:aws:iam::11111111111:root",
        "password_last_used": oldDate,    
        "access_key_1_last_used_date": null,
        "access_key_2_last_used_date": null,
    },
    {
        "user": "kms_key_recovery",
        "arn": "arn:aws:iam::11111111111:user/kms_key_recovery",
        "password_last_used": oldDate,    
        "access_key_1_last_used_date": null,
        "access_key_2_last_used_date": null,
    },
    {
        "user": "kms_key_recovery",
        "arn": "arn:aws:iam::11111111111:user/kms_key_recovery",
        "password_last_used": oldDate,    
        "access_key_1_last_used_date": dayOldDate,
        "access_key_2_last_used_date": null,
    }
]

const createCache = (users) => {
    return {
        iam: {
            generateCredentialReport: {
                'us-east-1': {
                    data: users
                }
            }
        }
    }
}

describe('iamUserInUse', function () {
    describe('run', function () {
        it('should FAIL when IAM user account recently used', function (done) {
            const settings = {
                iam_user_account_in_use_days: 15
            };

            const cache = createCache([users[2]]);
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.equal('IAM user was last used 1 days ago');
                done();
            };

            iamUserInUse.run(cache, settings, callback, currentDate);
        })

        it('should PASS when IAM user account not recently used', function (done) {
            const settings = {
                iam_user_account_in_use_days: 15
            };

            const cache = createCache([users[1]]);

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            };

            iamUserInUse.run(cache, settings, callback, currentDate);
        })

        it('should ignore recently used root user', function (done) {
            const settings = {
                iam_user_account_in_use_days: 15
            }

            const cache = createCache([users[0], users[1]]);
            
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            };

            iamUserInUse.run(cache, settings, callback, currentDate);
        })
    })
})
