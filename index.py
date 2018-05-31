import json
import datetime
import hmac , hashlib
import os
import sys
import boto3
import base64
from botocore.exceptions import ClientError

''''
acknowledgements
     https://github.com/serverless/examples/blob/master/aws-node-github-webhook-listener/handler.js
     https://github.com/carlos-jenkins/python-github-webhooks/blob/master/webhooks.py
     https://github.com/nytlabs/github-s3-deploy/blob/master/index.js
     https://aws.amazon.com/blogs/compute/sharing-secrets-with-aws-lambda-using-aws-systems-manager-parameter-store/
'''


here = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(here, "library"))
from github import Github, GithubException

def get_secret():
    secret_name = "/prod/githubCopy/appConfig"
    endpoint_url = "https://secretsmanager.us-east-1.amazonaws.com"
    region_name = "us-east-1"
    secret = {}

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        print ("got error")
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
        else :
            print (e)
    else:
        print ("Getting secret")
        # Decrypted secret using the associated KMS CMK
        # Depending on whether the secret was a string or binary, one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']

        # Your code goes here.
    return json.loads(secret)


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




def handler(event, context):
    headers = event["headers"]
    sig = headers['X-Hub-Signature']
    githubEvent = headers['X-GitHub-Event']
    id = headers['X-GitHub-Delivery']
    plain_ret = {
            'statusCode': 401,
            'headers': { 'Content-Type': 'text/plain' },
            'body': "",
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
    secret = get_secret()
    print ("secret = ", secret)
    if secret is None:
        plain_ret['body'] = 'Internal Configuration Problems'
        plain_ret['statusCode'] = 500
        return plain_ret

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
        
    plain_ret['body']  = 'No processing done as event was not relevant'
    if githubEvent == 'push':
        repository = event['body']['repository']['name']
        print("push event detected for repository=" + repository)
        try:
            n = secret[repository]
            s3 = boto3.resource('s3')
            g = Github(n['github'])
            r = g.get_user().get_repo(repository)
            f_c = r.get_branches()
            matched_branches = [match for match in f_c if match.name == "master"]
            download_directory(r,matched_branches[0].commit.sha,"/", s3,n['bucket'], "temp")
            print("Downloaded repository to S3 location")
            plain_ret['body']  = "Push event processed"
            plain_ret['statusCode'] = 200
        except KeyError as e:
            plain_ret['body']  = 'push event not processed for this repository'
    
    plain_ret['statusCode'] = 200
    return plain_ret
