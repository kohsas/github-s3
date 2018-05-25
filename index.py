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

def download_directory(repository, sha, server_path, s3, bucket, basedir):
    contents = repository.get_dir_contents(server_path, ref=sha)
    for content in contents:
        if content.type == 'dir':
            download_directory(repository, sha, content.path, s3, bucket, basedir+"/"+content.path)
        else :
            try:
                path = content.path
                file_content = repository.get_contents(path, ref=sha)
                file_data = base64.b64decode(file_content.content)
                s3.Object(bucket, basedir + "/" +content.name).put(Body=file_data)
                print("writing file = ", content.name, " to s3 path = ", basedir + "/" +content.name)
            except (GithubException, IOError) as exc:
                print('Error processing %s: %s', content.path, exc)


'''' 
acknowledgements
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
    plain_ret = {
            'statusCode': 401,
            'headers': { 'Content-Type': 'text/plain' },
            'body': "",
            'timestamp': datetime.datetime.utcnow().isoformat()
        }

    if sig is None:
        plain_ret['body'] = 'No X-Hub-Signature found on request'
        return plain_ret
        
    if githubEvent is None:
        plain_ret['body'] = 'No X-Github-Event found on request'
        plain_ret['statusCode'] = 422
        return plain_ret
        
    if id is None :
        plain_ret['body']  = 'No X-Github-Delivery found on request'
        return plain_ret

    if secret:
        # Only SHA1 is supported
        header_signature = headers['X-Hub-Signature']
        if header_signature is None:
            plain_ret['body']  = 'No X-Hub-Signature found on request'
            plain_ret['statusCode'] = 403
            return plain_ret
            
        sha_name, signature = header_signature.split('=')
        print ("header_signature = ", header_signature)
        print ("sha_name = ", sha_name)
        print ("signature = ", signature)
        sha_name = sha_name.strip()
        if sha_name != 'sha1':
            plain_ret['body']  = 'Only sha1 is supported'
            plain_ret['statusCode'] = 501
            return plain_ret
            
        # HMAC requires the key to be bytes, but data is string -- FIXME
        ''''
        mac = hmac.new(str(secret), msg=str(event["body"]), digestmod=hashlib.sha1)
        if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
            print ("signature mismatch " , mac.hexdigest(), signature)
            plain_ret['body']  = 'Invalid signature'
            plain_ret['statusCode'] = 403
            return plain_ret
        '''
    
    #implement ping
    githubEvent = githubEvent.strip()
    if githubEvent == 'ping':
        plain_ret['body']  = 'pong'
        plain_ret['statusCode'] = 200
        return plain_ret
        
    if githubEvent == 'push':
        repository = event['body']['repository']['name']
        print("push event detected for repository=" + repository)
        s3 = boto3.resource('s3')
        g = Github("dce0f5d9d3bdc0e6ae5fe8a04340930e31beb5e5")
        r = g.get_user().get_repo(repository)
        f_c = r.get_branches()
        matched_branches = [match for match in f_c if match.name == "master"]
        download_directory(r,matched_branches[0].commit.sha,"/", s3, "www.sangraha.co.in", "temp")
        print("Downloaded repository to S3 location")
        
        plain_ret['body']  = "Push event processed"
        plain_ret['statusCode'] = 200
    
    plain_ret['body']  = 'No processing done as event was not relevant'
    plain_ret['statusCode'] = 200
    return plain_ret
