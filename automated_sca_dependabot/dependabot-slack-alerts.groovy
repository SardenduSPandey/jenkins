def jobParameters = [
    booleanParam(name: 'Send_Per_Repo_Notification', defaultValue: false,
        description: 'Send notification to individual channels'),
    string(name: 'Severity', defaultValue: 'high, critical',
        description: 'Keep empty to get all alterts. Severity filter.')
]

// Configure these organizations to monitor - update with your GitHub org names
def organizations  = ['demo-org-1', 'demo-org-2']
def useRepoChannel = params.Send_Per_Repo_Notification
def severity       = params.Severity?.trim()?.replace(' ', '')

properties([ parameters(jobParameters) ])
pipeline {
    agent any
    stages {
        stage('Fetch and Report Dependabot Alerts') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'github-token', variable: 'token')]) {
                        for (org in organizations) {
                            echo "Fetching $severity Dependabot alerts for org: ${org}"
                            def alerts = common_utils.fetchGithubDependabotAlerts(token, org, severity)

                            if (alerts) {
                                echo "Fetched ${alerts.size()} open alerts for ${org}"
                                def repoMap = summarizeDependabotAlertsByRepo(alerts)

                                if (useRepoChannel) {
                                    repoMap.each { repo ->
                                        def message = buildDependabotSlackMessagePerRepo(repo)
                                        def channel = common_utils.getSlackChannelRepoMapping(repo.key)
                                        common_utils.sendSlackNotification(currentBuild.result, errorMessage, channel)
                                        sleep 5
                                    }
                                } else {
                                    // Update credential IDs to match your Jenkins credentials configuration
                                    withCredentials([string(credentialsId: 'slack-bot-token', variable: 'slackToken'),
                                        string(credentialsId: 'slack-alerts-channel-id', variable: 'slackChannelId')]) {
                                            // build a single message per org
                                            def message = ":rotating_light: *Dependabot Security Alert Report*\n" +
                                                "*Organization:* `${org}`   |   *Date:* ${new Date().format('yyyy-MM-dd')}\n" +
                                                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

                                            def fileName = "full_report.csv"
                                            writeCSV file: fileName, records: getCSVmap(repoMap)
                                            def uploadResponse = common_utils.slackFileUpload(fileName, slackToken, slackChannelId,
                                                10000000, message)
                                            echo "Slack API Response: ${uploadResponse}"
                                            sh "rm -fr $fileName || true"
                                    }
                                }
                            } else {
                                common_utils.sendSlackNotification('SUCCESS',
                                    ":white_check_mark: *Dependabot Alert Report — `${org}`*\n\n" +
                                    "No open security alerts found. All repositories are clean.", 'alerts-channel')
                            }
                        }
                    }
                }
            }
        }
    }

    post {
        failure {
            script {
                def errorMessage = ":x: *Dependabot Pipeline Failed*\n" +
                    "*Job:* ${env.JOB_NAME} — Build #${env.BUILD_NUMBER}\n" +
                    "*Status:* ${currentBuild.result}\n" +
                    "*Error:* ${currentBuild.description ?: 'Check console output for details'}\n" +
                    "*Build URL:* ${env.BUILD_URL}"
                common_utils.sendSlackNotification(currentBuild.result, errorMessage, 'notifications-channel')
            }
        }
        always {
            cleanWs()
        }
    }
}

// Groups alerts by repo name, counts by severity
def summarizeDependabotAlertsByRepo(List alerts) {
    def repoMap = [:]

    for (alert in alerts) {
        def repo = alert?.repository?.name ?: 'unknown'
        def severity  = (alert?.security_advisory?.severity ?: 'unknown').toLowerCase()

        if (!repoMap.containsKey(repo)) {
            repoMap[repo] = [critical: 0, high: 0, medium: 0, low: 0, total: 0]
        }

        repoMap[repo]['total']++

        switch (severity) {
            case 'critical':
                repoMap[repo]['critical']++
                break
            case 'high':
                repoMap[repo]['high']++
                break
            case 'medium':
                repoMap[repo]['medium']++
                break
            case 'low':
                repoMap[repo]['low']++
                break
            default:
                echo "unknown type: $severity in\n-----$alert\n-----"
        }
    }
    return repoMap
}

// Builds one professional Slack message per org covering all its repos
@NonCPS
def buildDependabotSlackMessagePerRepo(repoMap) {
    def lines = []
    lines << ":rotating_light: *Dependabot Security Alert Report*"
    lines << "*Repository:* `${repoMap.key}`   |   *Date:* ${new Date().format('yyyy-MM-dd')}"
    lines << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    lines << "*Total Open Alerts:* ${repoMap.value.total}   |   *Critical:* ${repoMap.value.critical}   |   *High:* ${repoMap.value.high}"
    lines << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    lines << ""
    lines << "_Please review and remediate Critical and High severity alerts at the earliest. Contact the Security team for assistance._"

    return lines.join('\n')
}

@NonCPS
def getCSVmap(repoMap) {
    def sortedRepos = repoMap.sort { a, b ->
    (b.value.total as Integer) <=> (a.value.total as Integer)
    }

    return [['Repository', 'Critical', 'High', 'Medium', 'Low', 'Total']] +
        sortedRepos.collect { repo, stats ->
            [
                repo,
                stats.critical ?: 0,
                stats.high ?: 0,
                stats.medium ?: 0,
                stats.low ?: 0,
                stats.total ?: 0
            ]
        }
}
