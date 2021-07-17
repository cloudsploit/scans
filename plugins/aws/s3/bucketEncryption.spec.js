var assert = require('assert');
var expect = require('chai').expect;
var s3 = require('./bucketEncryption');

const createCache = (cmk, bucketErr, sseAes, kms, cfMatching) => {
    var bucketObj = {};
    var cfobject = {};

    if (bucketErr) {
        bucketObj = {
            "err": {
              "message": "The server side encryption configuration was not found",
              "code": "ServerSideEncryptionConfigurationNotFoundError"
            }
        };
    } else if (sseAes) {
        bucketObj = {
            "data": {
              "ServerSideEncryptionConfiguration": {
                "Rules": [
                  {
                    "ApplyServerSideEncryptionByDefault": {
                      "SSEAlgorithm": "AES256"
                    }
                  }
                ]
              }
            }
        };
    } else if (kms) {
        bucketObj = {
            "data": {
              "ServerSideEncryptionConfiguration": {
                "Rules": [
                  {
                    "ApplyServerSideEncryptionByDefault": {
                      "SSEAlgorithm": "aws:kms",
                      "KMSMasterKeyID": "arn:aws:kms:us-east-1:0123456789101:key/abc0123"
                    }
                  }
                ]
              }
            }
        };
    }

    if (cfMatching) {
      cfobject = {
        "Id": "S3-bucket1",
        "DomainName": "bucket1.s3.amazonaws.com",
        "S3OriginConfig": {
          "OriginAccessIdentity": "origin-access-identity/cloudfront/ABCDEF123"
        }
      };
    } else {
      cfobject = {
        "Id": "S3-bucket2",
        "DomainName": "bucket2.s3.amazonaws.com",
        "S3OriginConfig": {
          "OriginAccessIdentity": "origin-access-identity/cloudfront/ABCDEF123"
        }
      };
    }

    return {
      "kms": {
        "listKeys": {
          "us-east-1": {
            "data": [
              {
                "KeyId": "abc0123",
                "KeyArn": "arn:aws:kms:us-east-1:0123456789101:key/abc0123"
              }
            ]
          }
        },
        "describeKey": {
          "us-east-1": {
            "abc0123": {
              "data": {
                "KeyMetadata": {
                  "KeyId": "abc0123",
                  "Arn": "arn:aws:kms:us-east-1:0123456789101:key/abc0123",
                  "Description": cmk ? "My key" : "Default master key that protects my S3 objects when no other key is defined",
                  "KeyManager": cmk ? "CUSTOMER" : "AWS"
                }
              }
            }
          }
        },
        "listAliases": {
          "us-east-1": {
            "data": [
              {
                "AliasName": "alias/my-alias",
                "AliasArn": "arn:aws:kms:us-east-1:0123456789101:alias/my-alias",
                "TargetKeyId": "abc0123"
              }
            ]
          }
        }
      },
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
        "getBucketEncryption": {
          "us-east-1": {
            "bucket1": bucketObj
          }
        },
        "getBucketLocation": {
          'us-east-1': {
            "bucket1": {
              data: {
                LocationConstraint: 'us-east-1'
            }
          }
        }
      },
      },
      "cloudfront": {
        "listDistributions": {
          "us-east-1": {
            "data": [
              {
                "Origins": {
                  "Items": [
                    cfobject
                  ]
                }
              }
            ]
          }
        }
      }
    }
};

describe('bucketEncryption', function () {
    describe('run', function () {
        it('should give failing result if S3 bucket has no encryption', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('has encryption disabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, true, false, false);

            s3.run(cache, {}, callback);
        })

        it('should give passing result if S3 bucket has AES encryption', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has AES256 encryption enabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, false, true, false);

            s3.run(cache, {}, callback);
        })

        it('should give passing result if S3 bucket has AWS KMS encryption', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has aws:kms encryption enabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, false, false, true);

            s3.run(cache, {}, callback);
        })

        it('should give passing result if S3 bucket has CMK KMS encryption', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has aws:kms encryption enabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(true, false, false, true);

            s3.run(cache, {}, callback);
        })

        it('should give passing result if unencrypted S3 bucket matches whitelist', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('is whitelisted via custom setting')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, true, false, false);

            s3.run(cache, {
              s3_encryption_allow_pattern: '^bucket1$'
            }, callback);
        })

        it('should give failing result if unencrypted S3 bucket does not match whitelist', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('has encryption disabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, true, false, false);

            s3.run(cache, {
              s3_encryption_allow_pattern: '^bucket2$'
            }, callback);
        })

        it('should give failing result if S3 bucket has AES encryption with opt-out', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('but is not using a CMK')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, false, true, false);

            s3.run(cache, {s3_encryption_require_cmk: 'true'}, callback);
        })

        it('should give failing result if S3 bucket has AWS KMS encryption with opt-out', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('but is not using a CMK')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, false, false, true);

            s3.run(cache, {s3_encryption_require_cmk: 'true'}, callback);
        })

        it('should give passing result if S3 bucket has CMK KMS encryption with opt-out', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has aws:kms encryption enabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(true, false, false, true);

            s3.run(cache, {s3_encryption_require_cmk: 'true'}, callback);
        })

        it('should give passing result if S3 bucket has CMK KMS encryption with provided alias', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has aws:kms encryption enabled using required KMS key')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(true, false, false, true);

            s3.run(cache, {s3_encryption_kms_alias: 'alias/my-alias'}, callback);
        })

        it('should give passing result if S3 bucket has CMK KMS encryption with one of provided aliases', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has aws:kms encryption enabled using required KMS key')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(true, false, false, true);

            s3.run(cache, {s3_encryption_kms_alias: 'alias/some-other-alias,alias/my-alias'}, callback);
        })

        it('should give failing result if S3 bucket has CMK KMS encryption without provided alias', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('but matching KMS key alias alias/my-unknown-alias could not be found in the account')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(true, false, false, true);

            s3.run(cache, {s3_encryption_kms_alias: 'alias/my-unknown-alias'}, callback);
        })

        it('should give passing result if S3 bucket requires CMK but has AES256 KMS encryption as a CloudFront origin', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has AES256 encryption enabled without a CMK but is a CloudFront origin')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, false, true, false, true);

            s3.run(cache, {
              s3_encryption_require_cmk: 'true',
              s3_encryption_allow_cloudfront: 'true'
            }, callback);
        })

        it('should give passing result if S3 bucket requires alias but has AES256 KMS encryption as a CloudFront origin', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has AES256 encryption enabled but is a CloudFront origin')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, false, true, false, true);

            s3.run(cache, {
              s3_encryption_kms_alias: 'alias/my-alias',
              s3_encryption_allow_cloudfront: 'true'
            }, callback);
        })

        it('should give failing result if S3 bucket requires alias but has AES256 KMS encryption not as a CloudFront origin', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('encryption (AES256) is not configured to use required KMS key')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, false, true, false, false);

            s3.run(cache, {
              s3_encryption_kms_alias: 'alias/my-alias',
              s3_encryption_allow_cloudfront: 'true'
            }, callback);
        })
    })
});