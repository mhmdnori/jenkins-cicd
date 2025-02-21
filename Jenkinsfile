pipeline {
    agent any

    tools{
        jdk 'jdk17'
        nodejs 'nodejs18'
    }

    environment {
        SONAR_HOST_URL = 'http://localhost:9001'
        SCANNER_HOME='SonarScanner'
    }

    stages {
        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }

        stage('Checkout') {
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: 'main']],
                    userRemoteConfigs: [[url: 'https://github.com/mhmdnori/jenkins-cicd.git']],
                    extensions: [[$class: 'CleanBeforeCheckout']]
                ])
            }
        }

        stage('Download Trivy Database') {
            steps {
                script {
                    sh '''
                        export TRIVY_DB_REPOSITORY="ghcr.io/aquasecurity/trivy-db"
                        trivy image --download-db-only
                    '''
                }
            }
        }

        stage('Trivy FileSystem Scan') {
            steps {
                script {
                    try {
                        sh 'trivy fs --severity HIGH,CRITICAL,MEDIUM --format table -o trivy-fs-report.html .'
                        archiveArtifacts artifacts: 'trivy-fs-report.html', allowEmptyArchive: true

                        def reportContent = readFile('trivy-fs-report.html')
                        if (reportContent.contains("CRITICAL") || reportContent.contains("HIGH")) {
                            error "Critical or High severity vulnerabilities found in the filesystem scan. Aborting the pipeline!"
                        }
                    } catch (Exception e) {
                        echo "Trivy filesystem scan failed: ${e.getMessage()}"
                        currentBuild.result = 'FAILURE'
                        throw e
                    }
                }
            }
        }

        stage('Dependency-Check Analysis') {
            steps {
                dependencyCheck odcInstallation: 'SCA', 
                                additionalArguments: '''
                                    --project "my-project"
                                    --scan ./ 
                                    --out ./reports/dependency-check
                                    --format JSON 
                                    --enableExperimental
                                    --failOnCVSS 7.0
                                    --data /var/lib/jenkins/dependency-check-data
                                '''
            }
        }

        stage('Publish Dependency-Check Results') {
            steps {
                dependencyCheckPublisher pattern: '**/reports/dependency-check/dependency-check-report.json', 
                                        failedNewHigh: 1, 
                                        failedTotalCritical: 0, 
                                        stopBuild: true
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarScanner') {
                    withCredentials([string(credentialsId: 'SONARQUBE_TOKEN', variable: 'SONARQUBE_TOKEN')]) {
                        script {
                            echo "Running SonarQube Analysis..."
                            sh '''
                            set +x
                                sonar-scanner \
                                  -Dsonar.projectKey=my-project \
                                  -Dsonar.sources=. \
                                  -Dsonar.host.url=$SONAR_HOST_URL \
                                  -Dsonar.login=$SONARQUBE_TOKEN
                            '''

                            archiveArtifacts artifacts: 'sonar-report.json', fingerprint: true
                        }
                    }
                }
            }
        }

        stage('Build & Tag Docker Image') {
            steps {
                script {
                    withDockerRegistry(credentialsId: 'docker-cred', toolName: 'docker') {
                        sh "docker build -t testapp ."
                        sh "docker tag testapp mohammad9195/testapp:latest"
                    }
                }
            }
        }

        stage('Trivy Image Scan') {
            steps {
                script {
                    try {
                        def imageName = 'mohammad9195/testapp:latest'
                        def reportJson = 'trivy-image-report.json'
                        def reportTxt = 'trivy-image-report.txt'

                        sh "trivy image --severity HIGH,CRITICAL,MEDIUM --format json -o ${reportJson} ${imageName}"
                        sh "trivy image --severity HIGH,CRITICAL --format table -o ${reportTxt} ${imageName}"

                        archiveArtifacts artifacts: 'trivy-image-report.json', allowEmptyArchive: true
                        archiveArtifacts artifacts: 'trivy-image-report.txt', allowEmptyArchive: true

                        def trivyReport = readJSON file: reportJson
                        def criticalCount = trivyReport.Vulnerabilities.findAll { it.Severity == "CRITICAL" }.size()
                        def highCount = trivyReport.Vulnerabilities.findAll { it.Severity == "HIGH" }.size()

                        if (criticalCount > 0 || highCount > 5) {
                            error "Build failed due to security vulnerabilities: CRITICAL=${criticalCount}, HIGH=${highCount}"
                        }
                    } catch (Exception e) {
                        echo "Trivy image scan failed: ${e.getMessage()}"
                        currentBuild.result = 'FAILURE'
                        throw e
                    }
                }
            }
        }

        stage('Push Docker Image') {
            steps {
                script {
                    withDockerRegistry(credentialsId: 'docker-cred', toolName: 'docker') {
                        sh "docker push mohammad9195/testapp:latest"
                    }
                }
            }
        }

        stage('Deploy To Container') {
            steps {
                sh "docker run -d -p 80:80 mohammad9195/testapp:latest"
            }
        }
    }
}
