var assert = require('assert');
var expect = require('chai').expect;
var ses = require('./sesValidatedDomains');

const createCache = (lData, gData) => {
    return {
        ses: {
            listIdentities: {
                'us-east-1': {
                    err: null,
                    data: lData
                }
            },
            getIdentityVerificationAttributes: {
                'us-east-1': {
                    err: null,
                    data: gData
                }
            }

        }
    }
};

describe('sesValidatedDomains', function () {
    describe('run', function () {
        it('should give passing result if no domain identities are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No SES domain identities found')
                done()
            };

            const cache = createCache(
                [],
                []
            );

            ses.run(cache, {}, callback);
        })
    });

    describe('run', function () {
        it('should give error result if verified domain identities exist', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Domain identity exists and is verified')
                done()
            };

            const cache = createCache(
                [{
                    "Identities": [
                        "test@test.com"
                    ]
                }],
                {
                    "VerificationAttributes": [
                        {
                            "VerificationStatus": "Success"
                        }
                    ]
                }
            );

            ses.run(cache, {}, callback);
        })
    })

    describe('run', function () {
        it('should give warning result if verified domain identities are pending', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Domain identity exists and has verification that is pending')
                done()
            };

            const cache = createCache(
                [{
                    "Identities": [
                        "test@test.com"
                    ]
                }],
                {
                    "VerificationAttributes": [
                        {
                            "VerificationStatus": "Pending"
                        }
                    ]
                }
            );

            ses.run(cache, {}, callback);
        })
    })

    describe('run', function () {
        it('should give warning result if domain identity exists, but verification has not yet been requested', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Domain identity exists with unknown status')
                done()
            };

            const cache = createCache(
                [{
                    "Identities": [
                        "test@test.com"
                    ]
                }],
                {
                    "VerificationAttributes": [
                        {}
                    ]
                }
            );

            ses.run(cache, {}, callback);
        })
    })

})