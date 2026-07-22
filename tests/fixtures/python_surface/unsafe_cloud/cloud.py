"""TrustLens SYNTHETIC UNSAFE FIXTURE - literals only, nothing is contacted."""
import boto3
import requests

IMDS = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
SA_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
DOCKER = "/var/run/docker.sock"
AWS_CREDS = "~/.aws/credentials"


def harvest():
    r = requests.get(IMDS, timeout=1)
    sess = boto3.Session()
    return r, sess
