package NAC.policy
import data.NAC.policy_demo.rules
import data.NAC.group_policy_demo.grouprules

test[result]{
    attr:=input.inputattributes[_]
    #Load the user and resource information
    user:=input.resource.users[_]
    resource:=input.resource.resources[_]
    #Load the user inline policies
    policy:= rules[_]

    policy_object:={policy|attr["UserName"]==policy["Subject"]["Subject"]}
    
    UserACL:= Match_user_inline_policy(policy_object,resource)

    #Find the user group name
    GroupName:=Retrieve_Group_Name(user,attr["UserName"])[_]
    
    #Load group inline policies
    GroupPolicy:=grouprules[_]

    #Find the group policy that matches the user that has requested access
    ReturnPolicy:={GroupPolicy|GroupPolicy["Subject"]["Subject"]==GroupName}
    
    result:=UserACL
    
}
#Find the group name the user belongs to
Retrieve_Group_Name(namelist,name)=groupname{
    groupname:={namelist["GroupName"]|namelist["UserName"]==name}
}

#Find the user_inline policies that the user match
Match_user_inline_policy(policy_object,resource)=ACL_dic{
    policy_object_NetworkInterface:={policy_object[_]["Object"]["ResourceId"] |policy_object[_]["Object"]["NetworkInterface"]=="None"}
    res_object_NetworkInterface:={resource["NetworkInterface"]|resource["InstanceId"]==policy_object_NetworkInterface[_]}

    policy_object_Tags:={policy_object[_]["Object"]["ResourceId"] |policy_object[_]["Object"]["Tags"]=="None"}
    res_object_Tags:={resource["Tags"]|resource["InstanceId"]==policy_object_Tags[_]}

    policy_object_InstanceType:={policy_object[_]["Object"]["ResourceId"] |policy_object[_]["Object"]["InstanceType"]=="None"}
    res_object_PlatformType:={resource["PlatformType"]|resource["InstanceId"]==policy_object_Tags[_]}

    policy_object_Subnet:={policy_object[_]["Object"]["ResourceId"] |policy_object[_]["Object"]["Subnet"]=="None"}
    res_object_Subnet:={resource["Subnet"]|resource["InstanceId"]==policy_object_Subnet[_]}

    policy_object_IPaddress:={resource["IPAddress"]|resource["InstanceId"] == policy_object[_]["Object"]["ResourceId"]}

    new_object_InstanceType:={"Meta":policy_object[_]["Meta"],"Object":{"Service":policy_object[_]["Object"]["Service"],"AvailabilityZone":policy_object[_]["Object"]["AvailabilityZone"],"AccountId":policy_object[_]["Object"]["AccountId"],
    "ResourceId":policy_object[_]["Object"]["ResourceId"],"VPCId":policy_object[_]["Object"]["VPCId"],"Protocol":policy_object[_]["Object"]["Protocol"], "IPAddress":policy_object_IPaddress[_],"InstanceType":res_object_PlatformType[_], "NetworkInterface":res_object_NetworkInterface[_], "Tags":res_object_Tags[_], "Subnet":res_object_Subnet[_]}}
    ACL_dic:={policy_object[_]["Subject"],new_object_InstanceType}
}



