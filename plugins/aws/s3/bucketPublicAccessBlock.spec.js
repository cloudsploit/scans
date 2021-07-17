var expect = require('chai').expect;
var bucketPublicAccessBlock = require('./bucketPublicAccessBlock');

const createCache = (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }]
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            PublicAccessBlockConfiguration: {
                                BlockPublicAcls,
                                IgnorePublicAcls,
                                BlockPublicPolicy,
                                RestrictPublicBuckets,
                            },
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

const createCacheNoPublicAccessBlock = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }]
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    mybucket: {
                        err: {
                            code: 'NoSuchPublicAccessBlockConfiguration',
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

const createCacheNullListBuckets = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': null,
            },
        },
    };
};

const createCacheNullGetPublicAccessBlock = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    mybucket: null,
                },
            },
        },
    };
};

const createCacheEmptyListBucket = () => {
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

const createCacheErrorListBucket = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    error: {
                        message: 'bad error',
                    },
                },
            },
        },
    };
};

const createCacheErrorGetPublicAccessBlock = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    mybucket: {
                        error: {
                            message: 'bad error',
                        },
                    },
                },
            },
        },
    };
};

describe('bucketPublicAccessBlock', function() {
    describe('run', function() {
        it('should PASS if public access block is fully configured', function(done) {
            const cache = createCache(true, true, true, true);
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no buckets in account', function(done) {
            const cache = createCacheEmptyListBucket();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should do nothing if null listBuckets', function(done) {
            const cache = createCacheNullListBuckets();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error listing buckets', function(done) {
            const cache = createCacheErrorListBucket();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should FAIL if public access block is partially configured', function(done) {
            const cache = createCache(true, true, false, false);
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if public access block not found', function(done) {
            const cache = createCacheNoPublicAccessBlock();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if public access block not found', function(done) {
            const cache = createCacheNoPublicAccessBlock();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if public access block not found but whitelisted', function(done) {
            const cache = createCacheNoPublicAccessBlock();
            bucketPublicAccessBlock.run(cache, {
                s3_public_access_block_allow_pattern: 'mybucket'
            }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should do nothing if null getPublicAccessBlock', function(done) {
            const cache = createCacheNullGetPublicAccessBlock();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error getting public access block', function(done) {
            const cache = createCacheErrorGetPublicAccessBlock();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});