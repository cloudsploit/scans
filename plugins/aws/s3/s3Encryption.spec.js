var expect = require('chai').expect;
var s3Encryption = require('./s3Encryption');

const createCacheNoEncryption = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: JSON.stringify({
                                Version: '2008-10-17',
                                Statement: [{
                                    Effect: 'Deny',
                                    Principal: '*',
                                    Action: 's3:PutObject',
                                    Resource: 'arn:aws:s3:::mybucket/*',
                                }],
                            }),
                        },
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        },
    };
};

const createCacheSSE = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: JSON.stringify({
                                Version: '2008-10-17',
                                Statement: [{
                                    Effect: 'Deny',
                                    Principal: '*',
                                    Action: 's3:PutObject',
                                    Resource: 'arn:aws:s3:::mybucket/*',
                                    Condition: {
                                        StringNotEquals: {
                                            's3:x-amz-server-side-encryption': 'AES256',
                                        },
                                    },
                                }],
                            }),
                        },
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        },
    };
};

const createCacheAWSKMS = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: JSON.stringify({
                                Version: '2008-10-17',
                                Statement: [{
                                    Effect: 'Deny',
                                    Principal: '*',
                                    Action: 's3:PutObject',
                                    Resource: 'arn:aws:s3:::mybucket/*',
                                    Condition: {
                                        StringNotEquals: {
                                            's3:x-amz-server-side-encryption-aws-kms-key-id': ':aws:kms:us-east-1:111111111111:key/mykey',
                                        },
                                    },
                                }],
                            }),
                        },
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        },
        kms: {
            describeKey: {
                'us-east-1': {
                    mykey: {
                        data: {
                            KeyMetadata: {
                                Origin: 'AWS_KMS',
                                KeyManager: 'AWS',
                            },
                        },
                    },
                },
            },
        },
    };
};

const createCacheAWSCMK = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: JSON.stringify({
                                Version: '2008-10-17',
                                Statement: [{
                                    Effect: 'Deny',
                                    Principal: '*',
                                    Action: 's3:PutObject',
                                    Resource: 'arn:aws:s3:::mybucket/*',
                                    Condition: {
                                        StringNotEquals: {
                                            's3:x-amz-server-side-encryption-aws-kms-key-id': ':aws:kms:us-east-1:111111111111:key/mykey',
                                        },
                                    },
                                }],
                            }),
                        },
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        },
        kms: {
            describeKey: {
                'us-east-1': {
                    mykey: {
                        data: {
                            KeyMetadata: {
                                Origin: 'AWS_KMS',
                                KeyManager: 'CUSTOMER',
                            },
                        },
                    },
                },
            },
        },
    };
};

const createCacheExternalCMK = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: JSON.stringify({
                                Version: '2008-10-17',
                                Statement: [{
                                    Effect: 'Deny',
                                    Principal: '*',
                                    Action: 's3:PutObject',
                                    Resource: 'arn:aws:s3:::mybucket/*',
                                    Condition: {
                                        StringNotEquals: {
                                            's3:x-amz-server-side-encryption-aws-kms-key-id': ':aws:kms:us-east-1:111111111111:key/mykey',
                                        },
                                    },
                                }],
                            }),
                        },
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        },
        kms: {
            describeKey: {
                'us-east-1': {
                    mykey: {
                        data: {
                            KeyMetadata: {
                                Origin: 'EXTERNAL',
                                KeyManager: 'CUSTOMER',
                            },
                        },
                    },
                },
            },
        },
    };
};

const createCacheHSM = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: JSON.stringify({
                                Version: '2008-10-17',
                                Statement: [{
                                    Effect: 'Deny',
                                    Principal: '*',
                                    Action: 's3:PutObject',
                                    Resource: 'arn:aws:s3:::mybucket/*',
                                    Condition: {
                                        StringNotEquals: {
                                            's3:x-amz-server-side-encryption-aws-kms-key-id': ':aws:kms:us-east-1:111111111111:key/mykey',
                                        },
                                    },
                                }],
                            }),
                        },
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        },
        kms: {
            describeKey: {
                'us-east-1': {
                    mykey: {
                        data: {
                            KeyMetadata: {
                                Origin: 'AWS_CLOUDHSM',
                            },
                        },
                    },
                },
            },
        },
    };
};

const createCacheNoBuckets = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [],
                },
            },
        },
    };
};

describe('s3Encryption', function () {
    describe('run', function () {
        it('should PASS when there are no buckets', function (done) {
            const cache = createCacheNoBuckets();
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL when the bucket policy does not enforce encryption (below configured level)', function (done) {
            const cache = createCacheNoEncryption();
            s3Encryption.run(cache, { s3_required_encryption_level: 'awskms' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS BucketPolicy=SSE, Configured=SSE', function (done) {
            const cache = createCacheSSE();
            s3Encryption.run(cache, { s3_required_encryption_level: 'sse' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS BucketPolicy=AWSKMS, Configured=AWSKMS', function (done) {
            const cache = createCacheAWSKMS();
            s3Encryption.run(cache, { s3_required_encryption_level: 'awskms' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS BucketPolicy=AWSCMK, Configured=AWSCMK', function (done) {
            const cache = createCacheAWSCMK();
            s3Encryption.run(cache, { s3_required_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS BucketPolicy=EXTERNAL, Configured=EXTERNAL', function (done) {
            const cache = createCacheExternalCMK();
            s3Encryption.run(cache, { s3_required_encryption_level: 'externalcmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS BucketPolicy=HSM, Configured=HSM', function (done) {
            const cache = createCacheHSM();
            s3Encryption.run(cache, { s3_required_encryption_level: 'cloudhsm' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL BucketPolicy=AWSKMS, Configured=AWSCMK', function (done) {
            const cache = createCacheAWSKMS();
            s3Encryption.run(cache, { s3_required_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
