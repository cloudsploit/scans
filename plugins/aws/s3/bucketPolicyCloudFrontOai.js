var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Policy CloudFront OAI',
    category: 'S3',
    description: 'Ensures S3 bucket is origin to only one distribution and allows only that distribution.',
    more_info: 'Access to CloudFront origins should only happen via ClouFront URL and not from S3 URL or any source in order to restrict access to private data.',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html',
    recommended_action: 'Review the access policy for S3 bucket which is an origin to a CloudFront distribution. Make sure the S3 bucket is origin to only one distribution. ' +
        'Modify the S3 bucket access policy to allow CloudFront OAI for only the associated CloudFront distribution and restrict access from any other source.',
    apis: ['CloudFront:listDistributions', 'S3:listBuckets', 'S3:getBucketPolicy', 'S3:getBucketLocation'],
    compliance: {
        hipaa: 'HIPAA requires that access to protected information is controlled and audited. ' +
                'If an S3 bucket backing a CloudFront distribution does not require the end ' +
                'user to access the contents through CloudFront, this policy may be violated.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listDistributions = helpers.addSource(cache, source,
            ['cloudfront', 'listDistributions', region]);

        if (!listDistributions) return callback(null, results, source);

        if (listDistributions.err || !listDistributions.data) {
            helpers.addResult(results, 3,
                'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions));
            return callback(null, results, source);
        }

        if (!listDistributions.data.length) {
            helpers.addResult(results, 0, 'No S3 origins to check');
            return callback(null, results, source);
        }

        var s3OriginFound = false;
        var s3BucketAssociations = {};
        listDistributions.data.forEach(distribution => {
            if (distribution.Id &&
                distribution.DomainName &&
                distribution.DomainName.length &&
                distribution.Origins &&
                distribution.Origins.Items &&
                distribution.Origins.Items.length) {
                
                for (let origin of distribution.Origins.Items) {
                    if (origin.S3OriginConfig) {
                        s3OriginFound = true;
                        let bucketName = origin.DomainName.substring(0, origin.DomainName.indexOf('.s3.amazonaws.com'));
                        if (origin.S3OriginConfig.OriginAccessIdentity &&
                            origin.S3OriginConfig.OriginAccessIdentity.length) {

                            let oaiId = origin.S3OriginConfig.OriginAccessIdentity.substring(origin.S3OriginConfig.OriginAccessIdentity.lastIndexOf('/') + 1);
                            let cfUser = `arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity ${oaiId}`;
                            if (s3BucketAssociations[bucketName]) {
                                if (s3BucketAssociations[bucketName][distribution.Id]) s3BucketAssociations[bucketName][distribution.Id].push(cfUser);
                                else {
                                    s3BucketAssociations[bucketName][distribution.Id] = [cfUser];
                                }
                            } else {
                                s3BucketAssociations[bucketName] = {};
                                s3BucketAssociations[bucketName][distribution.Id] = [cfUser];
                            }
                        } else {
                            s3BucketAssociations[bucketName] = {};
                            s3BucketAssociations[bucketName][distribution.Id] = [];
                            return;
                        }
                    }
                }
            }
        });

        if (!s3OriginFound) {
            helpers.addResult(results, 0, 'No S3 origins found for CloudFront distributions');
            return callback(null, results, source);
        }

        async.each(Object.entries(s3BucketAssociations), function([bucketName, cfDistributions], cb){
            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucketName);

            if (Object.keys(cfDistributions).length > 1) {
                helpers.addResult(results, 2,
                    `S3 bucket is origin to more than one distributions which are these: ${Object.keys(cfDistributions).join(', ')}`,
                    bucketLocation, `arn:aws:s3:::${bucketName}`);
                return cb();
            }

            var distributionId = Object.keys(cfDistributions).toString();
            if (!s3BucketAssociations[bucketName][distributionId].length) {
                distributionId = Object.keys(cfDistributions).toString();
                helpers.addResult(results, 2,
                    `S3 bucket is origin to distribution "${distributionId}" without an origin access identity`,
                    bucketLocation, `arn:aws:s3:::${bucketName}`);
                return cb();
            }

            var getBucketPolicy = helpers.addSource(cache, source,
                ['s3', 'getBucketPolicy', region, bucketName]);
            if (getBucketPolicy && getBucketPolicy.err &&
                    getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 2,
                    `No bucket policy found for S3 bucket: ${bucketName}`,
                    bucketLocation, `arn:aws:s3:::${bucketName}`);
                return cb();
            }
            
            if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3,
                    `Error querying for bucket policy for bucket "${bucketName}": ${helpers.addError(getBucketPolicy)}`,
                    bucketLocation, `arn:aws:s3:::${bucketName}`);
                return cb();
            }

            var statements = helpers.normalizePolicyDocument(getBucketPolicy.data.Policy);

            if (!statements || !statements.length) return cb();

            var unknownPrincipals = [];
            var restrictedOrigins = [];
            var allowedOrigins = [];
            for (var statement of statements) {
                var principals = helpers.extractStatementPrincipals(statement);

                for (var principal of principals) {
                    if (statement.Effect &&
                                statement.Effect.toUpperCase() === 'ALLOW' &&
                                !s3BucketAssociations[bucketName][distributionId].includes(principal) &&   
                                !unknownPrincipals.includes(principal)) {
                        unknownPrincipals.push(principal);
                    }

                    if (statement.Effect &&
                                statement.Effect.toUpperCase() === 'DENY' &&
                                s3BucketAssociations[bucketName][distributionId].includes(principal) &&  
                                !restrictedOrigins.includes(principal)) {
                        restrictedOrigins.push(principal);
                    }

                    if (statement.Effect &&
                        statement.Effect.toUpperCase() === 'ALLOW' &&
                        s3BucketAssociations[bucketName][distributionId].includes(principal) &&   
                        !allowedOrigins.includes(principal)) {
                        allowedOrigins.push(principal);
                    }
                }
            }

            var missingOrigins = s3BucketAssociations[bucketName][distributionId].filter(function(item) {
                return !allowedOrigins.includes(item) && !restrictedOrigins.includes(item); 
            });

            restrictedOrigins = restrictedOrigins.concat(missingOrigins);

            if (unknownPrincipals.length || restrictedOrigins.length) {
                if (unknownPrincipals.length) {
                    helpers.addResult(results, 2,
                        `S3 bucket is origin to distribution "${distributionId}" and allows access to these unknown sources: ${unknownPrincipals.join(', ')}`,
                        bucketLocation, `arn:aws:s3:::${bucketName}`);
                }
                if (restrictedOrigins.length) {
                    helpers.addResult(results, 2,
                        `S3 bucket is origin to distribution "${distributionId}" and does not allow access to these CloudFront OAIs: ${restrictedOrigins.join(', ')}`,
                        bucketLocation, `arn:aws:s3:::${bucketName}`);
                }
            } else {
                helpers.addResult(results, 0,
                    `S3 bucket is origin to only one CloudFront distribution which is: ${distributionId}`, bucketLocation, `arn:aws:s3:::${bucketName}`);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};
