/**
 * Sanitized SonarQube scan pipeline
 * This pipeline focuses on running the SonarQube scanner. Other build
 * stages have been preserved as commented placeholders for documentation.
 */

def jobParameters = [
    string(defaultValue: '', name: 'Tag', description: 'Optional tag to build'),
    string(defaultValue: '', name: 'Committish', description: 'Optional commit or branch to build'),
    string(defaultValue: '21', name: 'Java_Version', description: 'Java version for the build.'),
    booleanParam(defaultValue: false, name: 'Send_Email_Notification'),
    booleanParam(defaultValue: true, name: 'Enable_Sonar_Scanner', description: 'Enable Sonar Scanner for code quality analysis.')
]

def tagName    = params.Tag.trim() ? params.Tag : ''
def committish = params.Committish.trim() ? params.Committish : ''
def runSonarScanner = params.Enable_Sonar_Scanner

properties([parameters(jobParameters)])

pipeline {
    agent { label 'sast-agent' }
    stages {
        // Checkout stage (kept minimal and generic)
        stage('Checkout') {
            steps {
                script {
                    // Replace SSH URL with your repo; sanitized here
                    def sshUrl = 'git@example.com:your-org/your-repo.git'
                    def branches = tagName ? "*/tags/${tagName}" : (committish ? "*/${committish}" : '*/main')
                    def refspec = tagName ? '+refs/tags/*:refs/remotes/origin/tags/*' : '+refs/heads/*:refs/remotes/origin/heads/*'

                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: branches]],
                        userRemoteConfigs: [[url: sshUrl, refspec: refspec]],
                        extensions: [[$class: 'CloneOption', depth: 1, shallow: true]]
                    ])
                }
            }
        }

        // SonarQube scanner stage - primary focus of this pipeline
        stage('Run Sonar Scanner in Container') {
            when { expression { return runSonarScanner } }
            steps {
                sh '''
                  docker run --rm \
                    -v ${WORKSPACE}:/workspace \
                    -w /workspace \
                    sonarsource/sonar-scanner-cli \
                    sh -c "sonar-scanner"
                '''
            }
        }

        // Commented: build stages preserved for documentation only
        // stage('Amber Build') {
        //     steps {
        //         script {
        //             // Placeholder: build steps using Ant/Maven/Gradle go here
        //         }
        //     }
        // }

        // stage('Archive and Upload') {
        //     steps {
        //         script {
        //             // Placeholder: artifact packaging and upload to storage
        //         }
        //     }
        // }
    }

    post {
        success {
            script {
                if (params.Send_Email_Notification) {
                    def to = 'devops@example.com'
                    def subject = "${env.JOB_NAME} - Build #${env.BUILD_NUMBER}"
                    def body = "SonarQube scan completed successfully. See job: ${env.BUILD_URL}"
                    mail body: body, subject: subject, to: to
                }
            }
        }
        failure {
            script {
                if (params.Send_Email_Notification) {
                    def to = 'devops@example.com'
                    def subject = "${env.JOB_NAME} - Build #${env.BUILD_NUMBER} - FAILED"
                    def body = "SonarQube scan failed. See job: ${env.BUILD_URL}"
                    mail body: body, subject: subject, to: to
                }
            }
        }
        always {
            script {
                cleanWs()
            }
        }
    }
}

// Helper: minimal file exists check wrapper (kept for parity)
def filePatternExists(fileNamePattern) {
    return sh(script: "[ -n \"$(find . -name '${fileNamePattern}' 2>/dev/null)\" ]", returnStatus: true)
}
