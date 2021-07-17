package s3.bucketversioning

default allow = false                               

allow = true {                                      
    count(violation) == 0                           
}

violation[name] { 
    #some i
    name := input.s3.listBuckets[location].data[_].Name
	region := location
	versioning := input.s3.getBucketVersioning[location][name].data.Status
	versioning == "Suspended"
}
# buckets for what status is Suspended
s3region1[region]  =  bucketNames {
	name := input.s3.listBuckets[location].data[_].Name
	region := location
	input.s3.getBucketVersioning[location][name].data.Status
    bucketNames := [name |
					name := input.s3.listBuckets[region].data[i].Name
					versioning := input.s3.getBucketVersioning[region][name].data.Status
					versioning == "Suspended"]
}

# Buckets for what no status,that means versioning is disabled
s3region2[region] = bucketNames {
	name := input.s3.listBuckets[location].data[_].Name
	region := location
	input.s3.getBucketVersioning[location][name].data
    bucketNames := [name |
					name := input.s3.listBuckets[region].data[i].Name
					not input.s3.getBucketVersioning[region][name].data.Status
					]
}
# viloation result shoudl be
## 1. location where we have both suspended and disabled buckets
## 2. location where we have only disabled buckets
## 3. location where we have only suspened buckets

# 1. union of location where we have suspened and disabled buckets
s3regionviolation[region] = bucketNames {
	s3region2[location]
	s3region1[location]
	region := location
    bucketNames := array.concat(s3region2[region], s3region1[region])
}

# 2. here we have only disabled buckets no suspended
s3regionviolation[region] = bucketNames {
	s3region2[location]
	not s3region1[location]
	region := location
    bucketNames := s3region2[region]
}

# 3. here we have suspended buckets no disabled
s3regionviolation[region] = bucketNames {
	not s3region2[location]
	s3region1[location]
	region := location
    bucketNames := s3region1[region]

}

# s3 buckets with versioning enabled
s3regionallowed := {region: bucketNames |
	name := input.s3.listBuckets[location].data[_].Name
	region := location
	input.s3.getBucketVersioning[location][name].data.Status
    bucketNames := [name |
					name := input.s3.listBuckets[region].data[i].Name
					versioning := input.s3.getBucketVersioning[region][name].data.Status
					versioning == "Enabled"]
}
