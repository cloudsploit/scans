module.exports = {
    aws: {
        // bucketVersioning2:{
        //     title: 'S3 Bucket Versioning through OPA',
        //     category: 'S3',
        //     description: 'Ensures object versioning is enabled on S3 buckets',
        //     path: './plugins/aws/s3/bucketversioning2.rego',
        //     apis: ['S3:listBuckets', 'S3:getBucketVersioning', 'S3:getBucketLocation'],
        //     rules: {
        //         2: 'data.s3.bucketversioning.fail',
        //         0: 'data.s3.bucketversioning.pass'
        //     }
        // },
        bucketVersioning3 :    './plugins/aws/s3/bucketversioning3.rego',
        sqsEncrypted2     :    './plugins/aws/sqs/sqsEncrypted2.rego'
        // sqsEncrypted:{
        //     title: 'SQS Encrypted through OPA',
        //     category: 'SQS',
        //     description: 'Ensures SQS encryption is enabled',
        //     path: './plugins/aws/sqs/sqsEncrypted.rego',
        //     apis: ['SQS:getQueueAttributes', 'SQS:listQueues'],
        //     rules: {
        //         2: 'data.sqs.encryption.fail',
        //         1: 'data.sqs.encryption.warn',
        //         0: 'data.sqs.encryption.pass'
        //     }
        // },
    }
};