import json
import datetime
import hmac , hashlib
import os

'''' acknowledgements
     https://github.com/serverless/examples/blob/master/aws-node-github-webhook-listener/handler.js
     https://github.com/carlos-jenkins/python-github-webhooks/blob/master/webhooks.py
'''

def handler(event, context):
    headers = event["headers"]
    secret = os.environ['GITHUB_WEBHOOK_SECRET']
    sig = headers['X-Hub-Signature']
    githubEvent = headers['X-GitHub-Event']
    id = headers['X-GitHub-Delivery']
    
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

        # HMAC requires the key to be bytes, but data is string
        mac = hmac.new(str(secret), msg=str(event["data"]), digestmod=hashlib.sha1)

        if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
            errMsg = 'Invalid signature'
            return {
                'statusCode': 403,
                'headers': { 'Content-Type': 'text/plain' },
                'body': errMsg
            }
    
    #implement ping
    if githubEvent == 'ping':
        errMsg = 'pong'
        return {
                'statusCode': 200,
                'headers': { 'Content-Type': 'text/plain' },
                'body': errMsg
            }
    
    data = {
        'output': 'Hello World',
        'timestamp': datetime.datetime.utcnow().isoformat()
    }
    return {'statusCode': 200,
            'body': json.dumps(data),
            'headers': {'Content-Type': 'application/json'}}
