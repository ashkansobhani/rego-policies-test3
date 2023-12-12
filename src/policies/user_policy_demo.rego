package policy_demo 

rules:=[
	{
		"Meta":{
			"CloudProvider":"AWS",
			"Effect":"Allow",
			"CloudAction":"RunInstances"
		},
		"Subject":{
			"Subject":"None"
		},
		"Object":{
			"Service":"ec2",
			"AvailabilityZone":"*",
			"AccountId":"*",
			"ResourceId":"Default",
			"VPCId":"0046a9afcfe1a0ee2",
			"Protocol":"None",
			"NetworkInterface":"None",
			"SecurityGroups":"None",
			"Tags":"None",
			"SubnetId":"0054ccad816aae5a8",
			"Subnet":"None",
			"InstanceType":"None",
		}
	},
	{
		"Meta":{
			"CloudProvider":"AWS",
			"Effect":"Allow",
			"CloudAction":"RunInstances"
		},
		"Subject":{
			"Subject":"None"
		},
		"Object":{
			"Service":"ec2",
			"AvailabilityZone":"*",
			"AccountId":"*",
			"ResourceId":"Default",
			"VPCId":"*",
			"Protocol":"None",
			"NetworkInterface":"None",
			"SecurityGroups":"None",
			"Tags":"None",
			"SubnetId":"None",
			"Subnet":"None",
			"InstanceType":"None",
		}
	},
	{
		"Meta":{
			"CloudProvider":"AWS",
			"Effect":"Allow",
			"CloudAction":"StartSession"
		},
		"Subject":{
			"Subject":"Shichao"
		},
		"Object":{
			"Service":"ec2",
			"AvailabilityZone":"us-east-2",
			"AccountId":"044848052357",
			"ResourceId":"068b899eb68f70b24",
			"VPCId":"None",
			"Protocol":"SSH",
			"NetworkInterface":"None",
			"SecurityGroups":"None",
			"Tags":"None",
			"SubnetId":"None",
			"Subnet":"None",
			"InstanceType":"None",
		}
	},
	{
		"Meta":{
			"CloudProvider":"AWS",
			"Effect":"Allow",
			"CloudAction":"StartSession"
		},
		"Subject":{
			"Subject":"Sogand"
		},
		"Object":{
			"Service":"ec2",
			"AvailabilityZone":"us-east-2",
			"AccountId":"044848052357",
			"ResourceId":"0c4cd76161f145677",
			"VPCId":"None",
			"Protocol":"SSH",
			"NetworkInterface":"None",
			"SecurityGroups":"None",
			"Tags":"None",
			"SubnetId":"None",
			"Subnet":"None",
			"InstanceType":"None",
		}
	},
	{
		"Meta":{
			"CloudProvider":"AWS",
			"Effect":"Allow",
			"CloudAction":"StartSession"
		},
		"Subject":{
			"Subject":"shichao.guan1@huawei.com"
		},
		"Object":{
			"Service":"ec2",
			"AvailabilityZone":"us-east-2",
			"AccountId":"044848052357",
			"ResourceId":"068b899eb68f70b24",
			"VPCId":"None",
			"Protocol":"SSH",
			"NetworkInterface":"None",
			"SecurityGroups":"None",
			"Tags":"None",
			"SubnetId":"None",
			"Subnet":"None",
			"InstanceType":"None",
		}
	},
	{
		"Meta":{
			"CloudProvider":"AWS",
			"Effect":"Allow",
			"CloudAction":"StartSession"
		},
		"Subject":{
			"Subject":"sogand.sadrhaghighi@huawei.com"
		},
		"Object":{
			"Service":"ec2",
			"AvailabilityZone":"us-east-2",
			"AccountId":"044848052357",
			"ResourceId":"0c4cd76161f145677",
			"VPCId":"None",
			"Protocol":"SSH",
			"NetworkInterface":"None",
			"SecurityGroups":"None",
			"Tags":"None",
			"SubnetId":"None",
			"Subnet":"None",
			"InstanceType":"None",
		}
	},
	{
		"Meta":{
			"CloudProvider":"AWS",
			"Effect":"Allow",
			"CloudAction":"StartSession"
		},
		"Subject":{
			"Subject":"ashkan.sobhani@huawei.com"
		},
		"Object":{
			"Service":"ec2",
			"AvailabilityZone":"us-east-2",
			"AccountId":"044848052357",
			"ResourceId":"06fe5a04aa0ce4b32",
			"VPCId":"None",
			"Protocol":"SSH",
			"NetworkInterface":"None",
			"SecurityGroups":"None",
			"Tags":"{'Name': 'Web Server 1'}",
			"SubnetId":"None",
			"Subnet":"None",
			"InstanceType":"None",
		}
	}
]