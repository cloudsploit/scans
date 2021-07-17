package s3.bucketversioning

__rego_metadata__ := {
    "id": "XYZ-1234",
    "title": "bucketversioning3",
    "version": "v1.0.0",
    "severity": "HIGH",
    "category": "S3",
    "description": "Ensures object versioning is enabled on S3 buckets",
    "apis": ["S3:getBucketVersioning", "S3:listBuckets", "S3:getBucketLocation"],
    "rules": {
                "0": "data.s3.bucketversioning.pass"
              }
}

# s3 buckets with versioning enabled
pass[res] {
	input.data.Status
	versioning := input.data.Status
	versioning == "Enabled"
	 res := {
        	    "msg": "Bucket has versioning enabled",
        	    "status": 0
        	}
}
