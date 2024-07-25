 # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 # SPDX-License-Identifier: MIT-0
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy of this
 # software and associated documentation files (the "Software"), to deal in the Software
 # without restriction, including without limitation the rights to use, copy, modify,
 # merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 # permit persons to whom the Software is furnished to do so.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 # INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 # PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 # OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import json
import boto3
import datetime
import os

# Define the region and container name
awsRegion = 'ap-southeast-1'
containerName = 'devopssapps'
containerTag = 'latest'  # Assuming you have a tag, you can change it accordingly

# Create SecurityHub and STS clients with the specified region
securityhub = boto3.client('securityhub', region_name=awsRegion)
sts = boto3.client('sts', region_name=awsRegion)

# Open Trivy vuln report & parse out vuln info
try:
    with open('results.json') as json_file:
        data = json.load(json_file)
except FileNotFoundError:
    print("The file 'results.json' was not found.")
    exit(1)
except json.JSONDecodeError:
    print("Error decoding JSON from 'results.json'.")
    exit(1)

# Check if the data list is empty
if not data:
    print("No data found in 'results.json'.")
    exit(1)

# Check if the first element contains the 'Vulnerabilities' key
if 'Vulnerabilities' not in data[0]:
    print("The key 'Vulnerabilities' was not found in the data.")
    exit(1)

# Process vulnerabilities
if data[0]['Vulnerabilities'] is None:
    print('No vulnerabilities')
else:
    for p in data[0]['Vulnerabilities']:
        cveId = str(p['VulnerabilityID'])
        cveTitle = str(p['Title'])
        cveDescription = str(p['Description'])
        cveDescription = (cveDescription[:1021] + '..') if len(cveDescription) > 1021 else cveDescription
        packageName = str(p['PkgName'])
        installedVersion = str(p['InstalledVersion'])
        fixedVersion = str(p['FixedVersion'])
        trivySeverity = str(p['Severity'])
        cveReference = str(p['References'][0])
        # Create ISO 8601 timestamp
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        # Map Trivy severity to ASFF severity
        if trivySeverity == 'LOW':
            trivyProductSev = int(1)
            trivyNormalizedSev = trivyProductSev * 10
        elif trivySeverity == 'MEDIUM':
            trivyProductSev = int(4)
            trivyNormalizedSev = trivyProductSev * 10
        elif trivySeverity == 'HIGH':
            trivyProductSev = int(7)
            trivyNormalizedSev = trivyProductSev * 10
        elif trivySeverity == 'CRITICAL':
            trivyProductSev = int(9)
            trivyNormalizedSev = trivyProductSev * 10
        else:
            print('No vulnerability information found')
            continue  # Skip to the next vulnerability if severity is not found
        try:
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': containerName + '/' + cveId,
                        'ProductArn': f'arn:aws:securityhub:{awsRegion}:{awsAccount}:product/aquasecurity/aquasecurity',
                        'AwsAccountId': awsAccount,
                        'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': {
                            'Product': trivyProductSev,
                            'Normalized': trivyNormalizedSev
                        },
                        'Title': f'Trivy found a vulnerability {cveId} in container {containerName}',
                        'Description': cveDescription,
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'More information on this vulnerability is provided in the hyperlink',
                                'Url': cveReference
                            }
                        },
                        'ProductFields': {'Product Name': 'Trivy'},
                        'Resources': [
                            {
                                'Type': 'Container',
                                'Id': f'{containerName}:{containerTag}',
                                'Partition': 'aws',
                                'Region': awsRegion,
                                'Details': {
                                    'Container': {'ImageName': f'{containerName}:{containerTag}'},
                                    'Other': {
                                        'CVE ID': cveId,
                                        'CVE Title': cveTitle,
                                        'Installed Package': f'{packageName} {installedVersion}',
                                        'Patched Package': f'{packageName} {fixedVersion}'
                                    }
                                }
                            },
                        ],
                        'RecordState': 'ACTIVE'
                    }
                ]
            )
            print(response)
        except Exception as e:
            print(e)
            raise
