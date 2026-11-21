pipeline {
  agent any

  environment {
    IMAGE_NAME = 'cloudsec-platform'
  }

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Install Dependencies') {
      steps { sh 'npm install --no-audit --no-fund' }
    }

    stage('Unit Tests') {
      steps { sh 'npm test' }
    }

    stage('Build Docker Image') {
      steps { sh 'docker build -t ${IMAGE_NAME}:${BUILD_NUMBER} .' }
    }
  }

  post {
    always {
      echo 'Pipeline finished. Review test output and Docker build status above.'
    }
    success {
      echo 'Cloud Security Misconfiguration Platform passed CI.'
    }
    failure {
      echo 'CI failed. Fix the reported stage before merging.'
    }
  }
}
