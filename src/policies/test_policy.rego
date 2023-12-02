package NAC.test_policy
import data.users
import data.NAC.policy_demo.rules


allowed[result]{
    attr:=inputattributes[_]
    #Load the user and resource information
    user:=data.users[_]
    #Load the user inline policies
    policy:= data.NAC.policy_demo.rules[_]

    result:={policy|attr["UserName"]==policy["Subject"]["Subject"]}
    
    }