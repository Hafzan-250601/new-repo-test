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
        sh 'trivy image --exit-code 0 --no-progress --severity HIGH,CRITICAL,MEDIUM devopsapps'
      }
    }
  }
}
