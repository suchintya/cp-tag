import json
import commands
import os

user 		= "<username>"
password 	= "<password>"
ip = "<ip where cp is deployed>"
true=True
false=False
null=None


# this function contains dummy logs, need to integrate with real time logs
def get_tag_assest():
    d = {"version":"0","id":"d9eaf876-86c6-0499-ca3f-6d6f5b3561e4","detail-type":"AWS API Call via CloudTrail","source":"aws.ec2","account":"069159957172","time":"2018-12-14T07:11:05Z","region":"us-east-2","resources":[],"detail":{"eventVersion":"1.05","userIdentity":{"type":"IAMUser","principalId":"AIDAJKQHA3FQPA5UWUT2S","arn":"arn:aws:iam::069159957172:user/Suchintya","accountId":"069159957172","accessKeyId":"ASIARAGSBGK2ISAIS5XF","userName":"Suchintya","sessionContext":{"attributes":{"mfaAuthenticated":"false","creationDate":"2018-12-14T07:06:26Z"}},"invokedBy":"signin.amazonaws.com"},"eventTime":"2018-12-14T07:11:05Z","eventSource":"ec2.amazonaws.com","eventName":"CreateTags","awsRegion":"us-east-2","sourceIPAddress":"165.225.34.95","userAgent":"signin.amazonaws.com","requestParameters":{"resourcesSet":{"items":[{"resourceId":"i-0ac0c97c76bda8dfb"}]},"tagSet":{"items":[{"key":"veritas-backup","value":"bronze2"}]}},"responseElements":{"requestId":"fbc65644-9fe1-46d4-929f-d972c46af5ca","_return":true},"requestID":"fbc65644-9fe1-46d4-929f-d972c46af5ca","eventID":"12cfd94d-30ca-4140-a5f8-623beecb42a6","eventType":"AwsApiCall"}}
    asset = d['detail']['requestParameters']['resourcesSet']['items'][0]["resourceId"]
    tag_value = d['detail']['requestParameters']['tagSet']['items'][0]["value"]
    region = d["region"]
    source = d["source"]
    source = source.replace(".", "-")
    assetid = source + "-" + region + "-" + asset
    return assetid, tag_value


def get_token():
    cmd = "curl -s -X POST -H 'Content-type: application/json' -d '{\"email\": \""+user+"\", \"password\": \""+password+"\" }' -k https://"+ip+":443/cloudpoint/api/v2/idm/login"
    status,output = commands.getstatusoutput(cmd)
    if status!=0 :
       raise Exception("Error to get token.."+str(output))
    output = json.loads(output)
    if 'accessToken' not in output:
        token = ""
        print("WARNING : accessToken not found in output..")
    else :
        token = output['accessToken']
    return token


def check_policy(tag_value):
    token = get_token()
    cmd = "curl -s -H 'authorization: Bearer " + token+ "' -H \"Content-type: application/json\" -X GET -k https://"+ip+":443/cloudpoint/api/v2/policies/"
    status, output = commands.getstatusoutput(cmd)
    output = json.loads(output)
    for policy in output:
        if policy["name"] == tag_value:
            return policy["id"]
    return False


def check_asset(asset_id):
    token = get_token()
    cmd = "curl -s -H 'authorization: Bearer " + token+ "' -H \"Content-type: application/json\" -X GET -k https://"+ip+":443/cloudpoint/api/v2/assets/" + asset_id
    status, output = commands.getstatusoutput(cmd)
    output = json.loads(output)
    if "errorCode" in output:
        print("asset is not protected by CloudPoint")
        return False
    return True
    
def apply_policy(asset_id, policy):
    token = get_token()
    cmd = "curl -k -H 'authorization: Bearer " + token+ "' -H \"Content-type: application/json\" -X PUT https://"+ip+":443/cloudpoint/api/v2/assets/"+asset_id+"/policies/" + policy_check
    status, output = commands.getstatusoutput(cmd)
    output = json.loads(output)
    print(status)

def lambda_handler(event, context):
    # TODO implement
    asset_id, tag_value = get_tag_assest()
    asset_check = check_asset(asset_id)
    policy_check = check_policy(tag_value)
    if isinstance(policy_check, unicode) and asset_check:
        print("lets apply policy to asset")
        apply_policy(asset_id, policy_check)
    else:
        print("cannot apply policy to asset")
        print("Reason 1 : CloudPoint might not have policy")
        print("Reason 2 : Asset is not protected by CloudPoint")
    
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
