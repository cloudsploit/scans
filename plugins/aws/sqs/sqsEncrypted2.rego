package sqs.encryption

__rego_metadata__ := {
    "title": "SQS Encrypted through OPA",
    "category": "SQS",
    "description": "Ensures SQS encryption is enabled",
    "apis": ["SQS:getQueueAttributes", "SQS:listQueues"],
    "rules": {
                "2": "data.sqs.encryption.fail",
                "1": "data.sqs.encryption.warn",
                "0": "data.sqs.encryption.pass"
            }
}
# encryption disabled
fail[res]  {
	input.data.Attributes
    not input.data.Attributes.KmsMasterKeyId
    res := {
        	    "msg": "The SQS queue does not use a KMS key for SSE",
        	    "status": 2
        	}
}


# encryption enabled with default key
warn[res]  {
	input.data.Attributes
	input.data.Attributes.KmsMasterKeyId
	input.data.Attributes.KmsMasterKeyId == "alias/aws/sqs"
    res := {
                "msg": "The SQS queue does not use a KMS key for SSE",
                "status": 1
           	}
}


# encryption enabled with CMK key
pass[res] {
    input.data.Attributes
	input.data.Attributes.KmsMasterKeyId
	keyid := input.data.Attributes.KmsMasterKeyId
	keyid != "alias/aws/sqs"
	res := {
               "msg": "The SQS queue does not use a KMS key for SSE",
               "status": 0
           }
}


