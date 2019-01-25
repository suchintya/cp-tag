import json
import commands
import os
from pprint import pprint


def get_tag_assets(event):
    resource_id = event['detail']['requestParameters']['resourcesSet']['items'][0]['resourceId']
    tag_value = event['detail']['requestParameters']['tagSet']['items'][0]['value']
    region = event["region"]
    source = event["source"]
    source = source.replace(".", "-")
    assetid = source + "-" + region + "-" + resource_id
    assetid = str(assetid)
    return(assetid, tag_value)

    
def get_token(user, password, url):
    print("-----getting token")
    cmd = "curl -s -X POST -H 'Content-type: application/json' -d '{\"email\": \""+user+"\", \"password\": \""+password+"\" }' -k https://"+url+":443/cloudpoint/api/v2/idm/login"
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
    
def check_policy(url, token, tag_value):
    print("------checking for policy")
    cmd = "curl -s -H 'authorization: Bearer " + token+ "' -H \"Content-type: application/json\" -X GET -k https://"+url+":443/cloudpoint/api/v2/policies/"
    status, output = commands.getstatusoutput(cmd)
    output = json.loads(output)
    for policy in output:
        if policy["name"] == tag_value:
            return policy["id"]
    return False
    
def check_asset(url, token, asset_id):
    print("-----checking for asset")
    cmd = "curl -s -H 'authorization: Bearer " + token+ "' -H \"Content-type: application/json\" -X GET -k https://"+url+":443/cloudpoint/api/v2/assets/" + asset_id
    status, output = commands.getstatusoutput(cmd)
    output = json.loads(output)
    if "errorCode" in output:
        return False
    return True
    
def apply_policy(url, token, asset_id, policy):
    print(asset_id)
    policy = str(policy)
    print(policy)
    cmd = "curl -k -H 'authorization: Bearer " + token+ "' -H \"Content-type: application/json\" -X PUT https://"+url+":443/cloudpoint/api/v2/assets/"+ asset_id +"/policies/" + policy
    status, output = commands.getstatusoutput(cmd)
    print(output)
    print(status)



def lambda_handler(event, context):
    
    (asset_id, tag_value) = get_tag_assets(event)
    
    user = os.environ['user']
    password = os.environ['password']
    url = os.environ['url']
    
    # token to authorise cmds
    token = get_token(user, password, url)
    
    # checking asset and policy in cloudpoint or not
    asset_check = check_asset(url, token, asset_id)
    policy_check = check_policy(url, token, tag_value)
    
    response_status = None
    
    if isinstance(policy_check, unicode):
        print("lets apply policy to asset")
        response_status = 200
        apply_policy(url, token, asset_id , policy_check)
    else:
        response_status = 500
        print("cannot apply policy to asset: Asset not protected by CloudPoint or Policy missing")
    
    return {
        'statusCode': response_status,
        'body': json.dumps('this will be changed in future')
    }
