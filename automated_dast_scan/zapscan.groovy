/**
 * OWASP ZAP Automated Security Scan Pipeline
 *
 * This Jenkins pipeline performs automated security testing using OWASP ZAP (Zed Attack Proxy)
 * with authenticated browser sessions powered by Playwright.
 *
 * Pipeline Flow:
 * 1. Install Dependencies - Sets up Node.js, Python, Playwright, and ZAP Python client
 * 2. Start ZAP Daemon - Launches OWASP ZAP in daemon mode and waits for it to be ready
 * 3. Generate Authentication - Runs Playwright test to create authenticated session (auth.json)
 * 4. Run Security Scan - Executes ZAP security scan using the authenticated session via Python script
 * 5. Post-Processing - Stops ZAP, compresses the HTML report, and uploads to Slack
 *
 * Key Features:
 * - Automated authentication using Playwright browser automation
 * - ZAP daemon readiness verification with configurable timeout
 * - Generates timestamped HTML security reports (zap_report_YYYY-MM-DD.html.gz)
 * - Optional notification step for report delivery
 * - Workspace cleanup after execution
 *
 * Prerequisites:
 * - Jenkins agent with ZAP installed
 * - Optional Jenkins credentials configured for notification delivery
 * - Required files in automated_dast_scan/:
 *   - login.spec.ts: Playwright authentication test
 *   - ZapScan.py: Python script for ZAP scanning
 *   - package.json: Node.js dependencies
 *
 * Configuration:
 * - zapPort: Port for ZAP proxy (default: 8091)
 * - zapHost: Host address for ZAP (default: 127.0.0.1)
 * - zapTimeout: Maximum wait time for ZAP startup in seconds (default: 300)
 *
 * @Demo Project
 * @version 1.0
 * @since 2025-11-17
 */

def zapPort = '8091'
def zapHost = '127.0.0.1'
def zapTimeout = 300 // 5 minutes timeout for ZAP to start
pipeline {
    agent { label 'build-agent' }
    stages {
        stage('Install Dependencies') {
            steps {
                script {
                    dir('automated_dast_scan') {
                            echo 'Installing Node.js and Python dependencies...'
                            // Install Playwright and its browsers, and any other dependencies from package.json
                            sh '''npm install
                                npx playwright install
                                python3 -m pip install --user playwright python-owasp-zap-v2.4
                                python3 -m playwright install
                            '''
                    }
                }
            }
        }

        stage('Start ZAP in Daemon Mode') {
            steps {
                script {
                    echo 'Starting OWASP ZAP in daemon mode...'
                    sh """
                        zap.sh -daemon -port ${zapPort} -host ${zapHost} -config api.disablekey=true > zap.log 2>&1 &
                        echo \$! > zap.pid
                    """
                    echo 'Waiting for ZAP to start completely...'
                    def zapReady = false
                    def startTime = System.currentTimeMillis()
                    def timeoutMs = zapTimeout.toInteger() * 1000

                    while (!zapReady && (System.currentTimeMillis() - startTime) < timeoutMs) {
                        try {
                            def response = httpRequest(
                                url: "http://${zapHost}:${zapPort}",
                                validResponseCodes: '100:599',  // Accept all HTTP codes to check status
                                timeout: 10,
                                quiet: true,
                                consoleLogResponseBody: false
                            )

                            if (response.status == 200 || response.status == 404) {
                                echo "ZAP is ready! HTTP response: ${response.status}"
                                zapReady = true
                            } else {
                                echo "ZAP not ready yet (HTTP ${response.status}). Waiting..."
                                sleep(10)
                            }
                        } catch (Exception e) {
                            echo "ZAP not responding yet (${e.message}). Waiting..."
                            sleep(10)
                        }
                    }

                    if (!zapReady) {
                        error "ZAP failed to start within ${zapTimeout} seconds"
                    }
                }
            }
        }

        stage('Generate Authentication File') {
            steps {
                script {
                    dir('automated_dast_scan') {
                        echo 'Running Playwright test (login.spec.ts) to generate auth.json...'
                        // This command runs your sample login test, which saves the session
                        sh 'npx playwright test login.spec.ts'
                        echo 'Verifying that auth.json was created...'
                        if (!fileExists("${WORKSPACE}/automated_dast_scan/auth.json")) {
                            error 'auth.json was not created. The login test may have failed.'
                        }
                        echo 'auth.json is ready in the workspace directory.'
                    }
                }
            }
        }

        stage('Run ZAP Security Scan') {
            steps {
                script {
                    echo 'Running authenticated ZAP scan via Python script (ZapScan.py)...'
                    dir('automated_dast_scan') {
                        sh 'python3 -u ZapScan.py'
                        def dateStamp = new Date().format('yyyy-MM-dd')
                        def archiveFileName = "zap_scan_${dateStamp}.gz"
                        sh "gzip -f -c zap_report.html > $archiveFileName"
                        echo 'Optional: upload the report to an external storage or notification service.'
                        // Example placeholder for notification integration:
                        // withCredentials([string(credentialsId: 'slack-token', variable: 'slackToken'),
                        //     string(credentialsId: 'slack-channel-id', variable: 'slackChannelId')]) {
                        //     echo 'Uploading the file to Slack.'
                        //     common_utils.slackFileUpload(archiveFileName, slackToken, slackChannelId, 10000000)
                        // }
                    }
                    echo 'ZAP security scan completed!'
                }
            }
        }
    }
    post {
        always {
            script {
                echo 'Stopping ZAP daemon...'
                sh '''
                    if [ -f zap.pid ]; then
                        ZAP_PID=$(cat zap.pid)
                        if ps -p $ZAP_PID > /dev/null; then
                            kill $ZAP_PID
                            echo "ZAP process (PID: $ZAP_PID) stopped"
                        fi
                        rm zap.pid
                    fi
                '''
                echo 'Deleting workspace directory...'
                cleanWs()
            }
        }
    }
}
