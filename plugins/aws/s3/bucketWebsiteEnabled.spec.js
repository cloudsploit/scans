var assert = require('assert');
var expect = require('chai').expect;
var s3 = require('./bucketWebsiteEnabled');

const createCache = (bucketErr, website) => {
    var bucketObj = {};

    if (bucketErr) {
        bucketObj = {
            "err": {
              "code": "NoSuchWebsiteConfiguration"
            }
        };
    } else if (website) {
        bucketObj = {
            "data": website
        };
    }

    return {
      "s3": {
        "listBuckets": {
          "us-east-1": {
            "data": [
              {
                "Name": "bucket1"
              }
            ]
          }
        },
        "getBucketWebsite": {
          "us-east-1": {
            "bucket1": bucketObj
          }
        },
        "getBucketLocation": {
          'us-east-1': {
              "bucket1": {
                "data": {
                  "LocationConstraint": 'us-east-1'
              }
            }
          }
        }
      }
    };
};

describe('bucketWebsiteEnabled', function () {
    describe('run', function () {
        it('should give passing result if S3 bucket has no website', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('does not have static website hosting enabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(true);

            s3.run(cache, {}, callback);
        })

        it('should give passing result if S3 bucket has no website config', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('does not have static website hosting enabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, {});

            s3.run(cache, {}, callback);
        })

        it('should give failing result if S3 bucket has website enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('has static website hosting enabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, {
              "website": "config"
            });

            s3.run(cache, {}, callback);
        })
    })
});