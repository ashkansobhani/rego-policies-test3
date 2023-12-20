
package NAC.policy

import data.NAC.policy_demo.rules
import data.NAC.group_policy_demo.grouprules
import future.keywords.if


#By default give no permissions, if there is a match, return the context
default permission:=false
default_rule=permission if{
    count(test)==0
}else={test}

test[result]{
    attr:=input.inputattributes[_]
    #Load the user and resource information
    user:=input.resource.users[_]

    resource:=input.resource.resources
    #Load the information from the resources
    ResourceList:=[resource[j]]
    #==============================================================================================================
    #                Find the matching policies from the "User_Inline" policies and resolve them
    #==============================================================================================================
    # #Load the user inline policies
    Policy:= rules

    # #Find the policy that is assigned to a user that is requesting the access (the access requet comes from input.json)
    RawPolicyObject:= [Policy[i] | attr["UserName"]==Policy[i]["Subject"]["Subject"]]

    #Check if the condition holds
    NoCondition:=[RawPolicyObject[raw_i]| not RawPolicyObject[raw_i].Condition]
    WithCondition:=[RawPolicyObject[i]|RawPolicyObject[i].Condition;check_condition(RawPolicyObject[_].Condition,user)==true]
    PolicyObject:=array.concat(WithCondition,NoCondition)
    
    #Find the None elements
    NoneList:=Find_None_Elements(PolicyObject)

    #Find the values  that were Non in the user_inline policy from the resources 
    ResElements:=Resolve_Policy(NoneList,ResourceList)
    # # UserACL:= Match_user_inline_policy(PolicyObject,resource)

    #Find the extra resource information from the resources.json(these values are not assigned in the policy at all)
    AdditionalInfo:=Extract_Info(NoneList,ResourceList)

    #Substitute the resolved elements (This is the object of all matched user inline policies that are resolved)
    NewElements:=Substitute_PolicyFields(PolicyObject,ResElements,AdditionalInfo)
    #==============================================================================================================
    # #                Find the matching policies from the "Group_Inline" policies and resolve them
    # #==============================================================================================================
    #Find the user group name
    # GroupNameTemp:=Retrieve_Group_Name(user,attr["UserName"])
    GroupName:=Retrieve_Group_Name(user,attr["UserName"])[_]
    
    #Load group inline policies
    GroupPolicy:=grouprules

    #Find the group policy that matches the user that has requested access
    RawGroupPolicyObject:=[GroupPolicy[lk]|GroupPolicy[lk]["Subject"]["Subject"]==GroupName]

    #Check if the condition holds
    GroupNoCondition:=[RawGroupPolicyObject[i]|not RawGroupPolicyObject[i].Condition]
    GroupWithCondition:=[RawGroupPolicyObject[i]|RawGroupPolicyObject[i].Condition;check_condition(RawGroupPolicyObject[_].Condition,user)==true]
    GroupPolicyObject:=array.concat(GroupWithCondition,GroupNoCondition)

    #Find the None elements in the group inline policies
    GroupNoneList:=Find_None_Elements(GroupPolicyObject)
    
    #Find the values that were Non in the group_inline policy from the resources 
    GroupResElements:=Resolve_Policy(GroupNoneList,ResourceList)
    
    #Find the extra resource information from the resources.json(these values are not assigned in the policy at all)
    GroupAdditionalInfo:=Extract_Info(GroupNoneList,ResourceList)
   
    #Substitute the resolved elements (This is the object of all matched user inline policies that are resolved)
    GroupNewElements:=Substitute_PolicyFields(GroupPolicyObject,GroupResElements,GroupAdditionalInfo)
    # # result:=type_name(policy)

    #FIXME:The polishing the result can be improved
    
    #Polish the result
    PolishNewElements:=[NewElements|HasKey(NewElements,"Meta")==true]
    PolishGroupNewElements:=[GroupNewElements|HasKey(GroupNewElements,"Meta")==true]
    # # PolishGroupNewElements:=[GroupNewElements|GroupNewElements.Meta][0]
    PolishResult:={PolishNewElements,PolishGroupNewElements}
    result_temp :=[PolishResult[res_index]|count(PolishResult[res_index])>0][0]
    result:=result_temp[0]
}

#Check condition

check_condition(out, attr) = output_function if {
	cond := out[_]
	operator := [key | cond[key]]
	value := [val | val = cond[operator[0]]]
	output_function := check_operator(value, attr, operator[0])
}
#Check the operator in the condition
is_StringEqual(operator) if {
	"StringLike" == operator
}
condition_check(val,attr) = eval_result if {
	left_side := [key | val[0][key]]
    right_side:=[val[0][key]]
    eval_result:=evaluate_condition(left_side[0],split(right_side[0],".")[1],attr)
}

#If the operator is supported call the function check_condition
check_operator(value, attr, op) = condition_check(value, attr) if {
	is_StringEqual(op)
} else = {false}

evaluate_condition(function_left_side,function_right_side,attr)=true if{
function_left_side==attr[function_right_side]
}



#Find the null elements in an object
Find_None_Elements(policy_obj)=ReturnSet{
#k : the index of the policy , l: The keys for which the value is None    
NoneElements:=[[k,l,policy_obj[k]["Object"]["ResourceId"]]| (policy_obj[k]["Object"][l]=="None")] 
ReturnSet:=NoneElements
} 

#Resolve the Non values with values retrieved from resources
Resolve_Policy(NoElements,res)=ResolvedElements{
    # ResolvedElements:=[[NoElements[index][0],NoElements[index][1],res[_][NoElements[index][1]],res[_]["IPAddress"],res[_]["PlatformType"]]| res[_]["InstanceId"]==NoElements[index][2]]
    ResolvedElements:=[[NoElements[index][0],NoElements[index][1],res[_][NoElements[index][1]]]| res[_]["InstanceId"]==NoElements[index][2]]
 }


#Extract the values that only exist in the resource
Extract_Info(extract_NoElements,extract_res)=ExtraInfo{
    ExtraInfo:=[[extract_NoElements[index][0],extract_res[_]["IPAddress"],extract_res[_]["PlatformType"]]| extract_res[_]["InstanceId"]==extract_NoElements[index][2]]
 }


#Substitue the resolved policy in the original policy based on the resources
Substitute_PolicyFields(policy_obj_sub,Res_Elements,additional_info)=NewList{

    #Give the list of possible indeces in the returned policies(how many policies are returned)
    PolicyIndeces:={k|policy_obj_sub[k]; k == Res_Elements[sub_index][0]}

    #The object containg the keys that were resolved from the reources
    AssignObject:={Res_Elements[inner_index][1]:Res_Elements[inner_index][2]|Res_Elements[inner_index];PolicyIndeces[sub_index]}#Object
    
    #The object containing the keys that don't exist in the policy(only exist in resources)
    # AddObject:={{"ID":sub_index,"IPAddress":additional_info[inner_index1][1],"InstanceType":additional_info[inner_index1][2]}| PolicyIndeces[sub_index]; additional_info[inner_index1]}
    AddObject:={"ResourceFields":{"ID":sub_index,"IPAddress":additional_info[inner_index1][1],"InstanceType":additional_info[inner_index1][2]}| PolicyIndeces[sub_index]; additional_info[inner_index1]}#Object

    #The keys that are not in the resolved list (only exists in the policy)
    PrevKeys:=[third_index|policy_obj_sub[first_index]["Object"][third_index]; PolicyIndeces[first_index];not contain(third_index,Res_Elements)]

    #The Meta and subject fields that are return from the policy
    MetaSubject:={"Meta":policy_obj_sub[p_index]["Meta"]|PolicyIndeces[p_index]}
    # ConditionCaluse:={"Condition":policy_obj_sub[p_index]["Condition"]|PolicyIndeces[p_index]}
    #The object fields from the policy that were not Non (didn't need to be resolved)
    PrevObject:= {third_index:policy_obj_sub[first_index]["Object"][third_index]|PolicyIndeces[first_index];not contain(third_index,Res_Elements)}
    # # PrevObject:={"Index":list| list:={{"ID":id_index, PrevKeys[pre_index]:policy_obj_sub[id_index]["Object"][PrevKeys[pre_index]]} |PolicyIndeces[id_index];PrevKeys[pre_index] }}

    # # IdObject:={"ID":index_id|PolicyIndeces[index_id]}
    # # PrevObjectArr:=BreakObject(PrevObject)
    
    #FIXME:There is an empty list created
    TempObj:=MergeObjects(PrevObject,AssignObject)
    UserACLObject:=MergeObjects(TempObj,AddObject)
    FinalUserACLObject:={"Object":UserACLObject}
    NewList:=MergeObjects(FinalUserACLObject,MetaSubject)
    # NewList:=MergeObjects(NewList1,ConditionCaluse)
}

#Check if an object contains a specific key
contain(elem,arr)=true{
    arr[_][1]==elem
}else=false

#Find the group name the user belongs to
Retrieve_Group_Name(namelist,name)=groupname{
    groupname:={namelist["GroupName"]|namelist["UserName"]==name}
}

#Merge two object
MergeObjects(FirstObject,SecondObject)=MergedObject{
    MergeKeys:={merge_key|some merge_key; _=FirstObject[merge_key]}|{merge_key|some merge_key; _=SecondObject[merge_key]}
    MergedObject:={merge_key:merge_value | merge_key:=MergeKeys[_]; merge_value:=pick(merge_key,SecondObject,FirstObject)}
}
pick(merge_key,obj1,_)=obj1[merge_key]
pick(merge_key,obj1,obj2)=obj2[merge_key] {not exists(obj1,merge_key)}
exists(thisobj,merge_key){_=thisobj[merge_key]}

#Breaks an Object of objects to an Array of objects
BreakObject(id_object)=BreakRet{
    BreakRet:=[{id_k:id_v}|id_object[id_k]; id_v:=id_object[id_k]]
}

#Check if a key exists in an object
HasKey(HasObject,HasKeyfield)=true{
    _=HasObject[HasKeyfield]
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




