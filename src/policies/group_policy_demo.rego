package NAC.group_policy_demo
grouprules:=[
    {
        "Meta": {
            "CloudAction": "RunInstances",
            "CloudProvider": "AWS",
            "Effect": "Allow"
        },
        "Object": {
            "AccountId": "*",
            "AvailabilityZone": "*",
            "InstanceType": "None",
            "NetworkInterface": "None",
            "Protocol": "None",
            "ResourceId": "Default",
            "SecurityGroups": "None",
            "Service": "ec2",
            "Subnet": "None",
            "SubnetId": "0054ccad816aae5a8",
            "Tags": "None",
            "VPCId": "0046a9afcfe1a0ee2"
        },
        "Subject": {
            "Subject": "None"
        }
    },
    {
        "Meta": {
            "CloudAction": "RunInstances",
            "CloudProvider": "AWS",
            "Effect": "Allow"
        },
        "Object": {
            "AccountId": "*",
            "AvailabilityZone": "*",
            "InstanceType": "None",
            "NetworkInterface": "None",
            "Protocol": "None",
            "ResourceId": "Default",
            "SecurityGroups": "None",
            "Service": "ec2",
            "Subnet": "None",
            "SubnetId": "None",
            "Tags": "None",
            "VPCId": "*"
        },
        "Subject": {
            "Subject": "None"
        }
    },
    {
        "Meta": {
            "CloudAction": "StartSession",
            "CloudProvider": "AWS",
            "Effect": "Allow"
        },
        "Object": {
            "AccountId": "044848052357",
            "AvailabilityZone": "us-east-2",
            "InstanceType": "None",
            "NetworkInterface": "None",
            "Protocol": "SSH",
            "ResourceId": "068b899eb68f70b24",
            "SecurityGroups": "None",
            "Service": "ec2",
            "Subnet": "None",
            "SubnetId": "None",
            "Tags": "None",
            "VPCId": "None"
        },
        "Subject": {
            "Subject": "Shichao"
        }
    },
    {
        "Meta": {
            "CloudAction": "StartSession",
            "CloudProvider": "AWS",
            "Effect": "Allow"
        },
        "Object": {
            "AccountId": "044848052357",
            "AvailabilityZone": "us-east-2",
            "InstanceType": "None",
            "NetworkInterface": "None",
            "Protocol": "SSH",
            "ResourceId": "0c4cd76161f145677",
            "SecurityGroups": "None",
            "Service": "ec2",
            "Subnet": "None",
            "SubnetId": "None",
            "Tags": "None",
            "VPCId": "None"
        },
        "Subject": {
            "Subject": "Sogand"
        }
    }
]