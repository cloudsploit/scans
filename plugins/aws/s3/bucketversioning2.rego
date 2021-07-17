package s3.bucketversioning

# buckets for what status is Suspended
fail[res] {
	name := input.s3.listBuckets[location].data[_].Name
	region := location
	input.s3.getBucketVersioning[location][name].data.Status
	versioning := input.s3.getBucketVersioning[region][name].data.Status
	versioning == "Suspended"
	res := {
	    "msg": sprintf("Bucket : %s has versioning disabled",[name]),
	    "arn": concat("",["arn:aws:s3:::",name]),
	    "region": "global",
	    "status": 2
	}
}

# Buckets for what no status,that means versioning is disabled
fail[res]  {
	name := input.s3.listBuckets[location].data[_].Name
	region := location
	input.s3.getBucketVersioning[location][name].data
	not input.s3.getBucketVersioning[region][name].data.Status
    res := {
    	    "msg": sprintf("Bucket : %s has versioning disabled",[name]),
    	    "arn": concat("",["arn:aws:s3:::",name]),
    	    "region": "global",
    	    "status": 2
    	}
}

# s3 buckets with versioning enabled
pass[res] {
	name := input.s3.listBuckets[location].data[_].Name
	region := location
	input.s3.getBucketVersioning[location][name].data.Status
	versioning := input.s3.getBucketVersioning[region][name].data.Status
	versioning == "Enabled"
	res := {
    	    "msg": sprintf("Bucket : %s has versioning enabled",[name]),
    	    "arn": concat("",["arn:aws:s3:::",name]),
    	    "region": "global",
    	    "status": 0
    	}
}
