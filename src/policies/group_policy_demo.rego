package NAC.group_policy_demo 

grouprules:=[
	{
		"Meta":{
			"CloudProvider":"AWS",
			"Effect":"Allow",
			"CloudAction":"StartSession"
		},
		"Subject":{
			"Subject":"WebAdmins"
		},
		"Object":{
			"Service":"ec2",
			"AvailabilityZone":"us-east-2",
			"AccountId":"044848052357",
			"ResourceId":"0931512a2e9865531",
			"VPCId":"None",
			"Protocol":"SSH",
			"NetworkInterface":"None",
			"SecurityGroups":"None",
			"Tags":"None",
			"SubnetId":"None",
			"Subnet":"None",
			"InstanceType":"None"
		},
		"Condition":
			[{"StringLike": {"IT": "User.Department"}}]
	}
]

