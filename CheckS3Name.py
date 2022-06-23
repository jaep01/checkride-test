from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
import re

class CheckS3Name(BaseResourceCheck):
    def __init__(self):
        name = "Check if the S3 name follows the naming convention"
        id = "CUSTOM_AWS_S3_Name_Check"
        supported_resources = ['aws_s3_bucket']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'bucket' in conf.keys():
            bucketname = conf['bucket'][0]
            pattern = re.compile("^bucket-[0-9$]")
            if re.fullmatch(pattern, bucketname):
                return CheckResult.PASSED
            else:
                return CheckResult.FAILED

'''
    def scan_resource_conf(self, conf):
        if 'bucket' in conf.keys():
            if conf['bucket'][0] == 'mybucketname':
                return CheckResult.PASSED
        return CheckResult.FAILED
'''

check = CheckS3Name()
