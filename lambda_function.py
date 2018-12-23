import json
import commands
import os

def get_tag_assets(event):
    instance_id = event['detail']['requestParameters']['resourcesSet']['items'][0]['resourceId']
    tag_value = event['detail']['requestParameters']['tagSet']['items'][0]['value']
    return(instance_id, tag_value)
    
def get_token(user, password, url):
    cmd = "curl -s -X POST -H 'Content-type: application/json' -d '{\"email\": \"%s\", \"password\": \"%s\" }' -k https://%s/cloudpoint/api/v2/idm/login"%(user,password,url)
    status,output = commands.getstatusoutput(cmd)
    print(output)
    if status!=0 :
       raise Exception("Error to get token.."+str(output))
    output = json.loads(output)
    if 'accessToken' not in output:
        token = ""
        print("WARNING : accessToken not found in output..")
    else :
        token = output['accessToken']
    return token

def lambda_handler(event, context):
    
    (instance_id, tag_value) = get_tag_assets(event)
    print(instance_id)
    print(tag_value)
    
    user = os.environ['user']
    password = os.environ['password']
    url = os.environ['url']
    
    token = get_token(user, password, url)
    print(token)
