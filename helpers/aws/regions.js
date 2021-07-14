// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html

var regions = [
    'us-east-1',        // Northern Virginia
    'us-east-2',        // Ohio
    'us-west-1',        // Northern California
    'us-west-2',        // Oregon
    'ca-central-1',     // Canada (Montreal)
    'eu-central-1',     // EU (Frankfurt)
    'eu-west-1',        // EU (Ireland)
    'eu-west-2',        // London
    'eu-west-3',        // Paris
    'eu-north-1',       // Stockholm
    'ap-northeast-1',   // Asia Pacific (Tokyo)
    'ap-northeast-2',   // Asia Pacific (Seoul)
    'ap-southeast-1',   // Asia Pacific (Singapore)
    'ap-southeast-2',   // Asia Pacific (Sydney)
    'ap-south-1',       // Asia Pacific (Mumbai)
    'sa-east-1',        // South America (São Paulo)
    'ap-east-1',        // Asia Pacific (Hong Kong)
    'me-south-1'        // Middle East (Bahrain)
];

module.exports = {
    default: ['us-east-1'],
    all: regions,
    optin: ['ap-east-1', 'me-south-1'],   // Regions that AWS disables by default
    acm: regions,
    apigateway: regions,
    athena: ['us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1',
        'eu-west-1', 'eu-central-1', 'eu-west-2', 'ap-southeast-1',
        'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2', 'ap-south-1'],
    cloudfront: ['us-east-1'], // CloudFront uses the default global region
    autoscaling: regions,
    iam: ['us-east-1'],
    route53: ['us-east-1'],
    route53domains: ['us-east-1'],
    s3: ['us-east-1'],
    s3control: ['us-east-1'],
    cloudformation: regions,
    cloudtrail: regions,
    cloudwatchlogs: regions,
    comprehend: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1',
        'eu-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-northeast-1',
        'ap-southeast-2', 'ap-northeast-2', 'ap-south-1', 'ca-central-1'],
    configservice: regions,
    dax: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'ap-northeast-1', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1'
    ],
    devopsguru: ['us-east-1', 'us-east-2', 'eu-west-1', 'us-west-2', 'ap-northeast-1'],
    dynamodb: regions,
    dlm: regions,
    dms: regions,
    ec2: regions,
    ecr: regions,
    eks: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'eu-central-1',
        'eu-west-2', 'eu-west-3', 'eu-north-1', 'ap-southeast-1', 'ap-northeast-1',
        'ap-southeast-2', 'ap-northeast-2', 'ap-south-1'],
    elasticbeanstalk: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1',
        'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'ap-northeast-1',
        'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'sa-east-1'],
    elastictranscoder: ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1',
        'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-south-1'],
    elb: regions,
    elbv2: regions,
    eventbridge: regions,
    emr: regions,
    es: regions,
    glue: regions,
    kinesis: regions,
    firehose: ['us-east-1', 'us-east-2', 'us-west-2', 'us-west-1',
        'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1',
        'ap-northeast-1', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'sa-east-1'],
    kms: regions,
    vpc: regions,
    flowlogs: regions,
    rds: regions,
    redshift: regions,
    cloudwatch: regions,
    ecs: regions,
    resourcegroupstaggingapi: regions,
    sagemaker: [
        'us-east-1', 'us-east-2', 'us-west-2', 'ap-northeast-1', 'ap-northeast-2',
        'ap-southeast-2', 'eu-central-1', 'eu-central-1', 'eu-west-1'],
    secretsmanager: regions,
    ses: [
        'us-east-1', 'us-west-2',
        'eu-west-1'],
    sns: regions,
    sqs: regions,
    ssm: regions,
    shield: ['us-east-1'],
    // SSE via KMS is only supported in some regions
    // even though SQS is supported in all regions.
    sqs_encrypted: ['us-east-1', 'us-east-2', 'us-west-2', 'us-west-1',
        'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1',
        'ap-northeast-1', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'sa-east-1'],
    sts: ['us-east-1'],
    transfer: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
        'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3'],
    lambda: regions,
    mwaa: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'eu-north-1', 'eu-central-1',
        'ap-southeast-2', 'ap-southeast-1', 'ap-northeast-1'],
    directconnect: regions,
    directoryservice: ['us-east-1', 'us-east-2', 'us-west-2', 'us-west-1', 'ca-central-1',
        'sa-east-1', 'eu-west-1', 'eu-central-1', 'eu-west-2',
        'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2',
        'ap-south-1'],
    efs: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-2', 'eu-west-1',
        'ap-northeast-2', 'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'eu-central-1'],
    support: ['us-east-1'],
    wafregional: regions,
    wafv2: regions,
    organizations: ['us-east-1'],
    guardduty: regions,
    workspaces: ['us-east-1', 'us-west-2', 'ca-central-1', 'sa-east-1',
        'eu-west-1', 'eu-central-1', 'eu-west-2', 'ap-southeast-1',
        'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2'],
    servicequotas: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1',
        'ap-south-1', 'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'sa-east-1'],
    xray: ['us-east-1', 'us-east-2', 'us-west-2', 'us-west-1',
        'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1',
        'ap-northeast-1', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1'],
    codestar: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-north-1'],
    codebuild: regions
};
