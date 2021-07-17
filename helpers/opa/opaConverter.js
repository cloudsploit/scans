var metadata ="package service.testTitle\
\r\n\r\n__rego_metadata__ := {\
    \r\n    \"id\": 1234,\
    \r\n    \"title\": \"testTitle\",\
    \r\n    \"version\": \"testVersions\",\
    \r\n    \"severity\": \"testSeverity\",\
    \r\n    \"category\": \"testCategory\",\
    \r\n    \"description\": \"testDescription\",\
    \r\n    \"apis\": apiList,\
    \r\n    \"rules\": {\
    \r\n                    \"0\": \"data.service.testTitle.pass\"\
    \r\n            }\
\r\n}"

// var failRule = "\r\nfail[res]  {conditionProperty\r\n\tres := {\r\n\t\t\t\t\"msg\": \"The service resource property value is not set to condition.value\",\r\n\t\t\t\t\"status\": 2\r\n\t\t\t}\r\n}\r\n\r\n\r\n";
var passRule = "\r\npass[res] {conditionProperty\r\n\tres := {\r\n\t\t\t   \"msg\": \"The service resource property value is set to condition.value\",\r\n\t\t\t   \"status\": 0\r\n\t\t   }\r\n}\r\n\r\n\r\n"

var convertToOpa = function(asl){
    var rego ,rules;
    var logicalAnd = false;
    var noLogicalOp = false;
    var conditionProperties = [];
    var newMetadata = metadata.replace("1234", asl.id);
    var testTitle = asl.title.split(" ").join("");
    newMetadata = newMetadata.replace(/testTitle/g, asl.title.split(" ").join(""));
    newMetadata = newMetadata.replace("testVersions", asl.asl.version);
    newMetadata = newMetadata.replace("testSeverity", asl.severity);
    newMetadata = newMetadata.replace("testCategory", asl.category);
    newMetadata = newMetadata.replace(/service/g, asl.category.toLowerCase());
    newMetadata = newMetadata.replace("testDescription", asl.description);
    var regoApi = [];
    var regoPassingCondition = [];
    //var regoFailingCondition = [];
    // var failingRuleDone = {};
    // failingRule = failRule;
    passingRule = passRule;
    for ( api of asl.asl.apis){
        regoApi.push('"'+api+'"');
    }
    var failingRule, passingRule, rules = '';
    newMetadata = newMetadata.replace("apiList", "[" + regoApi.join(", ") + "]");
    var conditions =  asl.asl.conditions;
    if (conditions.length === 1) noLogicalOp = true;
    conditions.forEach((condition) =>{
        // split on '.'
        // so if the property is like a.b.c ,we need to check  input.data.a.b exists and input.data.a.b.c exists and finally
        // the comparison for input.data.a.b.c
        var properties = condition.property.split('.');
        var prop = 'input.data';
        for ( let property of properties){
             let i = 0;
             prop = prop + '.' + property;
             if (regoPassingCondition.indexOf('\r\n\t' + prop) === -1) {
                 regoPassingCondition.push('\r\n\t' + prop);
             }
             // if (regoFailingCondition.indexOf('\r\n\tnot ' + prop) === -1) {
             //     regoFailingCondition.push('\r\n\tnot ' + prop);
             // }
        }
        condition.property = prop; // change the property to be like input.data.a.b.c
        if (conditionProperties.indexOf(prop) === -1) conditionProperties.push(prop);

        // if the value is string it should be within ""
        if (condition.transform && condition.transform === 'STRING'){
            condition.value = `"${condition.value}"`;
        }

        if (condition.op) {
            if (condition.transform && condition.transform == 'EACH' && condition) {
                // Recurse into the same function
                //TBD
            } else if (condition.op == 'EQ') {
                regoPassingCondition.push('\r\n\t' + condition.property + ' == ' + condition.value);
                //regoFailingCondition.push('\r\n\t' + condition.property + ' != ' + condition.value);
            } else if (condition.op == 'GT') {
                regoPassingCondition.push('\r\n\t' + condition.property + ' > ' + condition.value);
                //regoFailingCondition.push('\r\n\tnot' + condition.property + ' > ' + condition.value);
            } else if (condition.op == 'NE') {
                regoPassingCondition.push('\r\n\t' + condition.property + ' != ' + condition.value);
                //regoFailingCondition.push('\r\n\tnot' + condition.property + ' == ' + condition.value);
            } else if (condition.op == 'MATCHES') {
                //TBD
                //output := regex.match(pattern, value)
            } else if (condition.op == 'EXISTS') {
                condition.value = "exist";
            } else if (condition.op == 'ISTRUE') {
                regoPassingCondition.push('\r\n\t' + condition.property + ' == true');
                //regoFailingCondition.push('\r\n\t' + condition.property + ' != true');
            } else if (condition.op == 'ISFALSE') {
                regoPassingCondition.push('\r\n\t' + condition.property + ' == false');
                //regoFailingCondition.push('\r\n\t' + condition.property + ' != false');
            } else if (condition.op == 'CONTAINS') {
                // TBD
                // contains(string, search)
            }
        } else{
            return console.error("No operation found in condition");
        }
       // if (!noLogicalOp) {
            if ( noLogicalOp || conditions[1].logical == 'AND') {
                // if logical and
                if (!noLogicalOp && conditions[1].logical == 'AND') logicalAnd = true;
                let andProp = condition.property;
                let andVal =  condition.value;
                // regoFailingCondition.forEach(failC => {
                //     if(!failingRuleDone[failC]){
                //         failingRule = failRule;
                //         if (failC.includes('not')) {
                //             andProp = failC.split(" ");
                //             andProp = andProp[1];
                //             andVal = "exist";
                //         } else {
                //             andVal =  failC.split(" ");
                //             andVal = andVal[andVal.length - 1].replace(/"/g,'');
                //         }
                //         failingRule = failingRule.replace('property', andProp);  // replace property name
                //         failingRule = failingRule.replace('service', asl.category); //replace service name
                //         failingRule = failingRule.replace('condition.value', andVal); //replace value
                //         failingRule = failingRule.replace('conditionProperty', failC);
                //         rules += failingRule;
                //         failingRuleDone[failC] = true;
                //     }
                // });
                // regoFailingCondition = [];
            } else {
                passingRule = passRule;
                passingRule = passingRule.replace('property', condition.property); // replace property
                passingRule = passingRule.replace('service', asl.category); // replace the service
                passingRule = passingRule.replace('condition.value', condition.value); // replace the value
                // replace the condition with the the formed one
                passingRule = passingRule.replace('conditionProperty', regoPassingCondition.join(" "));
                rules += passingRule;
                regoPassingCondition = [];
            }
      // }
    });

    if(logicalAnd || noLogicalOp) {
        // if "and" or just a single condition all the passing condition will be part of one single partial rule
        passingRule = passingRule.replace('The service resource property value is set to condition.value', `all of ${conditionProperties.join(",")} properties of ${ asl.category} resource are matching the value`);
        passingRule = passingRule.replace('conditionProperty', regoPassingCondition.join(" "));
        rules += passingRule;
    }
    // else {
    //     /*if "or" all the failing conditions should be in a single partial rule (logical and)(D.Morgan's)*/
    //     failingRule = failingRule.replace("\conditionProperty", regoFailingCondition.join(" "));
    //     failingRule = failingRule.replace('property value is not set to condition.value', `${conditionProperties.join(",")} properties of ${ asl.category} resource are not matching the value`);
    //     rules += failingRule;
    // }
    rego = newMetadata + '\n' + rules;
    console.log("Rego is : \n" + rego);
}

var testASL = {
    title: "S3 Bucket Versioning New",
    description: "Ensures object versioning is enabled on S3 buckets",
    severity: "low",
    more_info: "Object versioning can help protect against the overwriting of objects or data loss in the event of a compromise.",
    recommended_action: "Enable Bucketversioning",
    link: "http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html",
    category: "S3",
    asl: {
        apis: [
            "S3:getBucketVersioning",
            "S3:listBuckets"
        ],
        version: 1,
        conditions: [
            {
                service: "s3",
                api: "getBucketVersioning",
                property: "Status",
                op: "EQ",
                value: "Enabled",
                override: false,
                transform: "STRING"
            }
        ]
    }
};

var testASL2 = {
    id: 992,
    title: "SNS Topic CMK Encryption new",
    description: "Ensures Amazon SNS topics are encrypted with KMS Customer Master Keys (CMKs).",
    severity: "low",
    more_info: "AWS SNS topics should be  encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys in order to have a more granular control over the SNS data-at-rest encryption and decryption process.",
    recommended_action: "Update SNS topics to use Customer Master Keys (CMKs) for Server-Side Encryption.",
    link: "https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
    category: "SNS",
    asl: {
        apis: [
            "SNS:getTopicAttributes",
            "SNS:listTopics"
        ],
        conditions: [
            {
                service: "sns",
                api: "getTopicAttributes",
                property: "Attributes.KmsMasterKeyId",
                op: "EXISTS",
                value: "",
                override: false,
                transform: "NONE"
            },
            {
                service: "sns",
                api: "getTopicAttributes",
                property: "Attributes.KmsMasterKeyId",
                op: "EQ",
                value: "alias/aws/sns",
                override: false,
                transform: "STRING",
                logical: "AND"
            }
        ],
        version: 1
    }
}

convertToOpa(testASL2);