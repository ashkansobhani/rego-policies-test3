package NAC.test_policy
import data.users
import data.NAC.policy_demo.rules


allowed[result]{

    result:={data.NAC.policy_demo.rules|inputattributes[_]["UserName"]==data.NAC.policy_demo.rules[_]["Subject"]["Subject"]}
    
    }