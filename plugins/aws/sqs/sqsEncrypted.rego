package sqs.encryption

default allow = false

allow = true {
    count(violation) == 0
}

violation[name] {
    some i
    name := input.sqs.getQueueAttributes[location][i].data.Attributes.QueueArn
	region := location
	not input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId
}

# encryption disabled
fail[res]  {
	region := location
	input.sqs.getQueueAttributes[location][_].data.Attributes
	name := input.sqs.getQueueAttributes[location][i].data.Attributes.QueueArn
    not input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId

     res := {
        	    "msg": sprintf("Bucket : 'The SQS queue %s does not use a KMS key for SSE'",[name]),
        	    "arn": name,
        	    "region": region,
        	    "status": 2
        	}
}


# encryption enabled with default key
warn[res]  {
	region := location
	input.sqs.getQueueAttributes[location][_].data.Attributes
	name := input.sqs.getQueueAttributes[location][i].data.Attributes.QueueArn
	input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId
	input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId == "alias/aws/sqs"
    res := {
                "msg": sprintf("Bucket : 'The SQS queue %s does not use a KMS key for SSE'",[name]),
                "arn": name,
                "region": region,
                "status": 1
            }
}


# encryption enabled with CMK key
pass[res] {
	region := location
	input.sqs.getQueueAttributes[location][_].data.Attributes
    name := input.sqs.getQueueAttributes[location][i].data.Attributes.QueueArn
	input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId
	input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId != "alias/aws/sqs"
	res := {
               "msg": sprintf("Bucket : 'The SQS queue %s does not use a KMS key for SSE'",[name]),
               "arn": name,
               "region": region,
               "status": 0
           }
}