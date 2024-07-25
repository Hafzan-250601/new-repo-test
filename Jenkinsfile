pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'docker build -t devopsapps .'
      }
    }
    stage('Scan') {
      steps {
        sh 'trivy image --format template --template "@contrib/asff.tpl" -o report.asff --exit-code 0 --severity HIGH,CRITICAL,MEDIUM --no-progress devopsapps'
        sh 'aws securityhub enable-import-findings-for-product --product-arn arn:aws:securityhub:ap-southeast-1::product/aquasecurity/aquasecurity'
      }
    }
    stage('Upload Findings to SecurityHub') {
      steps {
        sh 'cat report.asff | jq \'.Findings\''
        sh 'aws securityhub batch-import-findings --findings report.asff'
      }
    }
  }
}
