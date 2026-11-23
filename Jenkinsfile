pipeline {
  agent any

  triggers {
    githubPush()
  }

  environment {
    IMAGE_NAME = 'cloudsec-platform'
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Install Dependencies') {
      steps {
        script {
          if (isUnix()) {
            sh 'npm ci --no-audit --no-fund'
          } else {
            bat 'npm ci --no-audit --no-fund'
          }
        }
      }
    }

    stage('Unit Tests') {
      steps {
        script {
          if (isUnix()) {
            sh 'npm test'
          } else {
            bat 'npm test'
          }
        }
      }
    }

    stage('Build Docker Image') {
      steps {
        script {
          if (isUnix()) {
            sh "docker build -t ${IMAGE_NAME}:${BUILD_NUMBER} ."
          } else {
            bat "docker build -t %IMAGE_NAME%:%BUILD_NUMBER% ."
          }
        }
      }
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
