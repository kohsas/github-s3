import json
import datetime
import hmac , hashlib
import os
import sys
import boto3
import base64

here = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(here, "library"))

from github import Github, GithubException



'''' acknowledgements
     https://github.com/serverless/examples/blob/master/aws-node-github-webhook-listener/handler.js
     https://github.com/carlos-jenkins/python-github-webhooks/blob/master/webhooks.py
     https://github.com/nytlabs/github-s3-deploy/blob/master/index.js
     
'''

def handler(event, context):
    headers = event["headers"]
    secret = os.environ['GITHUB_WEBHOOK_SECRET']
    sig = headers['X-Hub-Signature']
    githubEvent = headers['X-GitHub-Event']
    id = headers['X-GitHub-Delivery']
    s3 = boto3.resource('s3')
    
    print (event)
    if sig is None:
        errMsg = 'No X-Hub-Signature found on request'
        return {
            'statusCode': 401,
            'headers': { 'Content-Type': 'text/plain' },
            'body': errMsg
        }
        
    if githubEvent is None:
        errMsg = 'No X-Github-Event found on request'
        return {
            'statusCode': 422,
            'headers': { 'Content-Type': 'text/plain' },
            'body': errMsg
        }
    if id is None :
        errMsg = 'No X-Github-Delivery found on request'
        return {
            'statusCode': 401,
            'headers': { 'Content-Type': 'text/plain' },
            'body': errMsg
            }

    if secret:
        # Only SHA1 is supported
        header_signature = headers['X-Hub-Signature']
        if header_signature is None:
            errMsg = 'No X-Hub-Signature found on request'
            return {
                'statusCode': 403,
                'headers': { 'Content-Type': 'text/plain' },
                'body': errMsg
            }
        sha_name, signature = header_signature.split('=')
        print ("header_signature = ", header_signature)
        print ("sha_name = ", sha_name)
        print ("signature = ", signature)
        sha_name = sha_name.strip()
        if sha_name != 'sha1':
            errMsg = 'Only sha1 is supported'
            return {
                'statusCode': 501,
                'headers': { 'Content-Type': 'text/plain' },
                'body': errMsg
            }
        # HMAC requires the key to be bytes, but data is string -- FIXME
        ''''
        mac = hmac.new(str(secret), msg=str(event["body"]), digestmod=hashlib.sha1)
        if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
            print ("signature mismatch " , mac.hexdigest(), signature)
            errMsg = 'Invalid signature'
            return {
                'statusCode': 403,
                'headers': { 'Content-Type': 'text/plain' },
                'body': errMsg
            }
        '''
    
    #implement ping
    if githubEvent == 'ping':
        errMsg = 'pong'
        return {
                'statusCode': 200,
                'headers': { 'Content-Type': 'text/plain' },
                'body': errMsg
            }
    if githubEvent == 'push':
        print("push event detected")
        
    
    data = {
        'output': 'Hello World',
        'timestamp': datetime.datetime.utcnow().isoformat()
    }
    return {'statusCode': 200,
            'body': json.dumps(data),
            'headers': {'Content-Type': 'application/json'}}
