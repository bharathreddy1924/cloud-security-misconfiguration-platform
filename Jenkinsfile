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
      steps { bat 'npm ci --no-audit --no-fund' }
    }

    stage('Unit Tests') {
      steps { bat 'npm test' }
    }

    stage('Build Docker Image') {
      steps { bat "docker build -t %IMAGE_NAME%:%BUILD_NUMBER% ." }
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
