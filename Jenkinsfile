pipeline {
    agent any
    
    environment {
        SCANNER_HOME= tool 'sonar-scanner'
    }

    stages {
        
        stage('Git Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/sanju2/jenkins-cicd-pipeline.git'
            }
        }
    
        stage('Trivy FileSystem Scan') {
            steps {
                sh "trivy fs --format table -o trivy-fs-report.html ."
            }
        }
    
        stage('Sonarqube Analysis') {
            steps {
                withSonarQubeEnv('sonar') {
                    sh "$SCANNER_HOME/bin/sonar-scanner -Dsonar.projectKey=jenkins -Dsonar.projectName=jenkins"
                }
            }
        }
    
        stage('Build & Tag Docker Image') {
            steps {
                script {
                        withDockerRegistry(credentialsId: 'docker-cred', toolName: 'docker') {
                            sh "docker build -t lasanthasanjeewa/testapp:v1 ."
                   }
                }
            }
        }
    
        stage('Trivy Image Scan') {
            steps {
                sh "trivy image --format json -o trivy-image-report.json lasanthasanjeewa/testapp:v1"
            }
        }
    
        stage('Push Docker Image') {
            steps {
                script {
                        withDockerRegistry(credentialsId: 'docker-cred', toolName: 'docker') {
                            sh "docker push lasanthasanjeewa/testapp:v1 "
                   }
                }
                
            }
        }
    
        stage('Deploy To Container') {
            steps {
                sh "docker run -d -p 8081:80 lasanthasanjeewa/testapp:v1"
            }
        }
    }
}
