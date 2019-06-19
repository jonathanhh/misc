import json
import boto3


def lambda_handler(event, context):
    # Parse SNS event for relevant information
    trigger = event['Records'][0]['Sns']['Message']['Trigger']
    dest = trigger['PrivateIP']
    instID = trigger['Dimensions']
    instance = str(instID)
    source = event['Records'][0]['Sns']['Message']['Attributes']['External']

    # Correct firewall on offending instance & log change (in addition to default lambda logs)
    command = 'sh iptables -A INPUT -i eth0 -p tcp --dport 22 ! -s 172.31.*/20 -j DROP'
    ssm = boto3.client('ssm')
    ssmresponse = ssm.send_command(
        InstanceIds=[instance],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [command]},
        CloudWatchOutputConfig={'CloudWatchLogGroupName': '/aws/lambda/SSH-Action', 'CloudWatchOutputEnabled': True}
    )
    print (ssmresponse)

    # Inform application owners
    sns = boto3.client('sns')
    response = sns.publish(
        TopicArn='arn:aws:sns:us-west-1:220103774467:ApplicationOwnerAlerts',
        Message=(
                    'Instance IP ' + dest + ' has been found non-compliant and action has been taken. Logs available in the CloudWatch group: /aws/lambda/SSH-Action'),
    )
    print (response)

    return {
        'errorExternal.IP': source,
        'body': json.dumps('Alert: External SSH Detected From: ' + source + ' To: ' + dest)
    }
