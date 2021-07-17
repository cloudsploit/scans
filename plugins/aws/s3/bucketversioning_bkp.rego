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

s3regionviolation := {region: bucketNames |
    
	name := input.s3.listBuckets[location].data[_].Name
	region := location
	input.s3.getBucketVersioning[location][name].data.Status
    bucketNames := [name |
					name := input.s3.listBuckets[region].data[i].Name
					versioning := input.s3.getBucketVersioning[region][name].data.Status
					versioning == "Suspended"]
}

s3regionallowed := {region: bucketNames |

	name := input.s3.listBuckets[location].data[_].Name
	region := location
	input.s3.getBucketVersioning[location][name].data.Status
    bucketNames := [name |
					name := input.s3.listBuckets[region].data[i].Name
					versioning := input.s3.getBucketVersioning[region][name].data.Status
					versioning == "Enabled"]
}



#app_to_hostnames[region] = bucketNames {
#
#    bucketNames := [name |
#					name := input.s3.listBuckets[location].data[i].Name
#					region := location
#					versioning := input.s3.getBucketVersioning[location][name].data.Status
#					versioning == "Suspended"]
#}