var expect = require('chai').expect;
const crossVpcPublicPrivate = require('./crossVpcPublicPrivate');

const describeSubnets = [
    {
        "AvailabilityZone": "ap-south-1b",
        "AvailabilityZoneId": "aps1-az3",
        "AvailableIpAddressCount": 4091,
        "CidrBlock": "172.31.0.0/20",
        "DefaultForAz": true,
        "MapPublicIpOnLaunch": true,
        "MapCustomerOwnedIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-c671028a",
        "VpcId": "vpc-b87396d3",
        "OwnerId": "111111111111",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "Tags": [],
        "SubnetArn": "arn:aws:ec2:ap-south-1:111111111111:subnet/subnet-c671028a"
    }
];
const describeRouteTables = [
    {
        "Associations": [
          {
            "Main": true,
            "RouteTableAssociationId": "rtbassoc-45aa0634",
            "RouteTableId": "rtb-36afd348",
            "AssociationState": {
              "State": "associated"
            }
          }
        ],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-36afd348",
        "Routes": [
          {
            "DestinationCidrBlock": "172.31.0.0/16",
            "GatewayId": "local",
            "Origin": "CreateRouteTable",
            "State": "active"
          },
          {
            "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": "igw-7f3e1a04",
            "Origin": "CreateRoute",
            "State": "active"
          }
        ],
        "Tags": [],
        "VpcId": "vpc-99de2fe4",
        "OwnerId": "111111111111"
    },
    {
        "Associations": [
          {
            "Main": true,
            "RouteTableAssociationId": "rtbassoc-45aa0634",
            "RouteTableId": "rtb-36afd348",
            "AssociationState": {
              "State": "associated"
            }
          }
        ],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-36afd348",
        "Routes": [
          {
            "DestinationCidrBlock": "172.31.0.0/16",
            "GatewayId": "local",
            "Origin": "CreateRouteTable",
            "State": "active"
          },
          {
            "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": "igw-7f3e1a04",
            "Origin": "CreateRoute",
            "State": "active"
          },
          {
            "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": "igw-7f3e1a04",
            "Origin": "CreateRoute",
            "State": "active",
            "VpcPeeringConnectionId": "vp-29de2fe4"
          }
        ],
        "Tags": [],
        "VpcId": "vpc-99de2fe4",
        "OwnerId": "111111111111"
    },
];
const describeVpcPeeringConnections = [
    {
        "VpcPeeringConnectionId": "vp-29de2fe4",
        "AccepterVpcInfo": {
            "VpcId": "vpc-19de2fe4",
            "CidrBlock": "172.31.0.0/20",
            "OwnerId": "111111111111",
        },
        "RequesterVpcInfo": {
            "VpcId": "vpc-99de2fe4",
            "CidrBlock": "172.31.0.0/20",
            "OwnerId": "111111111111"
        }
    }    
];

const createCache = (subnets, routeTables, peeredSubnets) => {
    return {
        ec2:{
            describeSubnets: {
                'us-east-1': {
                    data: subnets
                },
            },
            describeRouteTables: {
                'us-east-1': {
                    data: routeTables
                },
            },
            describeVpcPeeringConnections: {
                'us-east-1': {
                    data: peeredSubnets
                },
            },
        },
    };
};

const createSubnetErrorCache = (routeTables, peeredSubnets) => {
    return {
        ec2:{
            describeSubnets: {
                'us-east-1': {
                    err: {
                        message: 'error describing subnets'
                    },
                },
            },
            describeRouteTables: {
                'us-east-1': {
                    data: routeTables
                },
            },
            describeVpcPeeringConnections: {
                'us-east-1': {
                    data: peeredSubnets
                },
            },
        },
    };
};

const createRouteTableErrorCache = (subnets, peeredSubnets) => {
    return {
        ec2:{
            describeSubnets: {
                'us-east-1': {
                    data: subnets,
                },
            },
            describeRouteTables: {
                'us-east-1': {
                    err: {
                        message: 'error describing route tables'
                    },
                },
            },
            describeVpcPeeringConnections: {
                'us-east-1': {
                    data: peeredSubnets,
                },
            },
        },
    };
};

const createVpcPeeringErrorCache = (subnets, routeTables) => {
    return {
        ec2:{
            describeSubnets: {
                'us-east-1': {
                    data: subnets,
                },
            },
            describeRouteTables: {
                'us-east-1': {
                    data: routeTables,
                },
            },
            describeVpcPeeringConnections: {
                'us-east-1': {
                    err: {
                        message: 'error describing vpc peered subnets'
                    },
                },
            },
        },
    };
};

describe('crossVpcPublicPrivate', function () {
    describe('run', function () {
        it('should PASS if there is no vpc peering connection found', function (done) {
            const cache = createCache([describeSubnets[0]], [describeRouteTables[0]], []);
            crossVpcPublicPrivate.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if there are no public routes found', function (done) {
            const cache = createCache([describeSubnets[0]], [describeRouteTables[0]], [describeVpcPeeringConnections[0]]);
            crossVpcPublicPrivate.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        // test for public route found to be added
        
        it('should UNKNWON if unable to describe subnets', function (done) {
            const cache = createSubnetErrorCache();
            crossVpcPublicPrivate.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNWON if unable to describe route tables', function (done) {
            const cache = createRouteTableErrorCache();
            crossVpcPublicPrivate.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNWON unable to describe vpc peering connection subnets', function (done) {
            const cache = createVpcPeeringErrorCache();
            crossVpcPublicPrivate.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
