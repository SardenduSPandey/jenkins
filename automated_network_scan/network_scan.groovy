/*
  Automated network port scanning pipeline.

  Flow:
  1. On the `build-agent` agent, expand the selected datacenter inventories with
     `ansible-inventory` and build a single inventory_parsed.json file.
  2. On the `scan-agent` agent, run nmap for each selected datacenter, generate
     scan CSVs plus an unexpected-port report, and upload the results to Slack.
  3. Back on the `build-agent` agent, archive the generated reports and send a
     summary webhook message. Unexpected open ports mark the build UNSTABLE.
*/

def datacenters = common_utils.getDatacenterList().sort()
def parallelScanning  = params.Parallel_Scanning
def targetDatacenters = [:]
def isFullReport = params.Full_Port_Report

def jobParameters = [
    booleanParam(name: 'All', defaultValue: true,
        description: 'Scan every datacenter'),
    *(datacenters.collect { dc ->
        booleanParam(name: dc, defaultValue: false, description: "Scan ${dc}")
    }),
    booleanParam(name: 'Parallel_Scanning', defaultValue: true,
        description: 'Run selected datacenter scans in parallel on the scan-agent agents'
    ),
    booleanParam(name: 'Full_Port_Report', defaultValue: true,
        description: 'Is full port report required?'
    )
]

properties([parameters(jobParameters)])

pipeline {
    agent { label 'build-agent' }
    options { 
        disableConcurrentBuilds()
        // adjust accoring to pipeline needs
        timeout(time: 20, unit: 'HOURS')
        skipStagesAfterUnstable()
    }
    stages {
        stage('Build Inventory Plan') {
            steps {
                script {
                    targetDatacenters = getSelectedDcs(datacenters)
                    if (targetDatacenters.isEmpty()) {
                        error 'Select ALL or at least one datacenter to scan.'
                    }

                    def hosts = buildInventoryPlan(targetDatacenters)
                    if (hosts.isEmpty()) {
                        error 'No public IPs with inventory metadata were found in the selected datacenters.'
                    }

                    writeJSON file: 'inventory_parsed.json', json: [
                        total_ips      : hosts.size(),
                        datacenters    : targetDatacenters.collect { [name: it.name, prefix: it.prefix] },
                        hosts          : hosts,
                        scan_timestamp : new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX"),
                        generated_by_job: env.JOB_NAME,
                        generated_build : env.BUILD_NUMBER
                    ], pretty: 4

                    dir('automated-network-scan') {
                        stash name: 'network_scan_scripts', includes: '*.py'
                    }
                    stash name: 'network_scan_inventory', includes: 'inventory_parsed.json'

                    echo "Prepared ${hosts.size()} public IPs across ${targetDatacenters.size()} datacenter(s)."
                }
            }
        }

        stage('Run Network Scans') {
            steps {
                script {
                    def scanJobs = [:]

                    targetDatacenters.each { dc ->
                        def dcName = dc.name
                        def dcPrefix = dc.prefix
                        scanJobs[dcName] = runScanForDatacenter(dcName, dcPrefix)
                    }

                    if (parallelScanning && scanJobs.size() > 1) {
                        parallel scanJobs
                    } else {
                        scanJobs.each { _, job -> job.call() }
                    }
                }
            }
        }

        stage('Archive And Notify') {
            steps {
                script {
                    def summaries = []
                    def fullPortReport = "Datacenter, IP, Hostname, Port, Status, Service, Version\n"
                    def failedPortReport = "Datacenter, IP, Hostname, Port, Status," +
                        "Service, Version, Finding, Result, Allowed_Ports\n"
                    def weakCipherReport = "Datacenter, IP, TLS Version, Issue Type, Cipher Name\n"
                    def failureCount = 0
                    def weakCipherCount = 0

                    dir('artifacts') {
                        deleteDir()
                    }

                    targetDatacenters.each { dc ->
                        dir("artifacts/${dc.prefix}") {
                            deleteDir()
                            unstash "network_scan_results_${dc.prefix}"
                            unstash 'network_scan_scripts'
                            unstash 'network_scan_inventory'

                            sh """
                                set -euo pipefail
                                python3 nmap_xml_to_csv.py -o ${dc.prefix}.csv -dc ${dc.name} ${dc.prefix}.xml
                                python3 generate_report.py ${dc.prefix}
                                python3 cipher_xml_to_csv.py \
                                    -o ${dc.prefix}_Cipher.csv \
                                    -wo ${dc.prefix}_weak_ciphers.csv \
                                    -dc "${dc.name}" \
                                    ${dc.prefix}_tls.xml
                            """.stripIndent()

                            fullPortReport   += readFile file: "${dc.prefix}.csv"
                            failedPortReport += readFile file: "${dc.prefix}_unexpected_ports.csv"

                            def summary = readJSON file: "${dc.prefix}_scan_summary.json"
                            //array of json object
                            summaries << summary
                            failureCount += (summary.failure_count ?: 0) as int

                            def weakCsvText = readFile file: "${dc.prefix}_weak_ciphers.csv"
                            // drop the per-file header before appending to the aggregated report
                            def weakLines = weakCsvText.readLines()
                            weakCipherReport += weakLines.drop(1).join('\n') + '\n'
                            weakCipherCount  += weakLines.count { it.trim() && !it.startsWith('Datacenter') }
                        }
                    }

                    dir("artifacts") {
                        withCredentials([
                            string(credentialsId: 'slack-bot-token', variable: 'slackToken'),
                            string(credentialsId: 'slack-reports-channel-id', variable: 'slackChannelId'),
                            string(credentialsId: 'slack_webhook_url', variable: 'slackWebhookUrl')
                        ]) {
                            if (isFullReport) {
                                writeFile file: "full_report.csv", text: fullPortReport
                                common_utils.slackFileUpload("full_report.csv", slackToken, slackChannelId,
                                    10000000, "Open port scan results:"
                                )
                            }

                            if (failureCount > 0) {
                                writeFile file: "failed_port_report.csv", text: failedPortReport
                                common_utils.slackFileUpload("failed_port_report.csv", slackToken,
                                    slackChannelId, 10000000,
                                    "${failureCount} unexpected open port found! Please investigate inventory FWs, NSGs immediately!"
                                )
                            }

                            if (weakCipherCount > 0) {
                                writeFile file: "weak_ciphers_report.csv", text: weakCipherReport
                                common_utils.slackFileUpload(
                                    "weak_ciphers_report.csv", slackToken, slackChannelId, 10000000,
                                    "${weakCipherCount} weak cipher finding(s) detected! Please review."
                                )
                            }

                            common_utils.sendSlackMessage(buildSummaryMessage(summaries, weakCipherCount), slackWebhookUrl)
                        }
                    }

                    archiveArtifacts artifacts: 'artifacts/**/*.csv,artifacts/**/*_scan_summary.json', allowEmptyArchive: false
                    def totalUnexpectedPorts = summaries.sum { (it.failure_count ?: 0) as int }
                    if (totalUnexpectedPorts > 0) {
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
    }

    post {
        failure {
            script {
                withCredentials([
                    string(credentialsId: 'slack_webhook_url', variable: 'slackWebhookUrl')
                ]) {
                    common_utils.sendSlackMessage("Nmap scan failed! Job: ${env.BUILD_URL}", slackWebhookUrl)
                }
            }
        }
        always {
            cleanWs(deleteDirs: true)
        }
    }
}

def getSelectedDcs(datacenters) {
    def dcConfig = common_utils.getDcEnvConfig()
    def selectedNames = params.All ? datacenters : datacenters.findAll { dc ->
        params.containsKey(dc) && params[dc]
    }

    return selectedNames.collect { dc ->
        [
            name  : dc,
            prefix: dcConfig[dc].ansibleFilePrefix
        ]
    }
}

def buildInventoryPlan(List selectedDcs) {
    def inventoryHosts = [:]

    selectedDcs.each { dc ->
        def rawJson = sh(
            script: """
                set -euo pipefail
                cd ansible-config
                docker compose -f docker-compose.yml run --rm ansible \
                    ansible-inventory -i inventory/${dc.prefix}_ranges.yml --list
            """.stripIndent(),
            returnStdout: true
        ).trim()

        echo "JSON:------\n$rawJson\n-------"

        def inventory = readJSON text: rawJson.replace('\n','')
        def dcHosts = collectPublicHosts(inventory, dc)
        inventoryHosts.putAll(dcHosts)

        echo "Inventory ${dc.prefix}: ${dcHosts.size()} public IP(s) prepared for scanning."
    }

    return inventoryHosts
}

def collectPublicHosts(Map inventory, Map dc) {
    def hosts = [:]

    inventory.each { groupName, groupData ->
        if (groupName == '_meta' || !groupName.endsWith('_public_ips')) {
            return
        }

        def groupHosts = []
        if (groupData instanceof Map) {
            if (groupData.hosts instanceof List) {
                groupHosts = groupData.hosts
            } else if (groupData.hosts instanceof Map) {
                groupHosts = groupData.hosts.keySet().toList()
            }
        }

        groupHosts.each { ip ->
            def hostVars = inventory._meta?.hostvars?.get(ip) ?: [:]
            def allowedPorts = (hostVars.open_port instanceof List ? hostVars.open_port : [])
                .findAll { it != null && "${it}".trim() }
                .collect { "${it}".toInteger() }
                .unique()
                .sort()

            hosts[ip] = [
                datacenter      : dc.prefix,
                datacenter_name : dc.name,
                allowed_ports   : allowedPorts
            ]
        }
    }

    return hosts
}

def runScanForDatacenter(String dcName, String dcPrefix) {
    return {
        node('scan-agent') {
            stage("Scan ${dcName}") {
                dir("artifacts/${dcPrefix}") {
                    deleteDir()
                    unstash 'network_scan_inventory'

                    def inventory = readJSON file: 'inventory_parsed.json'
                    def dcHosts = inventory.hosts.findAll { ip, details ->
                        details.datacenter == dcPrefix
                    }

                    if (dcHosts.isEmpty()) {
                        echo "WARNING: No inventory targets for ${dcName} (${dcPrefix}). Skipping scan."
                        return
                    }

                    def fileName = "${dcPrefix}_targets.txt"
                    def ipList = dcHosts.keySet().sort().toList()

                    echo "Total IPs to scan: " + ipList.size()
                    writeFile file: fileName, text: ipList.join('\n') + '\n'

                    def portList = "25,443,587"
                    sh """
                        set -euo pipefail
                        nmap --script ssl-enum-ciphers -p ${portList} --host-timeout 3m --max-retries 1 -iL ${fileName} -oX ${dcPrefix}_tls.xml
                        nmap -Pn -sV --open -p- --host-timeout 15m --max-retries 1 -iL ${fileName} -oX ${dcPrefix}.xml
                    """.stripIndent()
                    stash(
                        name: "network_scan_results_${dcPrefix}",
                        includes: "${dcPrefix}.xml,${dcPrefix}_tls.xml"
                    )
                }
            }
        }
    }
}

def buildSummaryMessage(List summaries, int weakCipherCount = 0) {
    def totalFindings = summaries.sum { (it.failure_count ?: 0) as int }
    def totalIps = summaries.sum { (it.inventory_ip_count ?: 0) as int }
    def status = totalFindings > 0 ? 'UNSTABLE' : 'SUCCESS'
    def cipherStatus = weakCipherCount > 0 ? "${weakCipherCount} weak cipher(s) detected" : "No weak ciphers found"
    def details = summaries.collect { summary ->
        "${summary.datacenter}: ${summary.failure_count} unexpected port(s) across ${summary.inventory_ip_count} inventoried IP(s)"
    }.join('\n')

    return """\
        Network scan completed with status ${status}
        Datacenters: ${summaries.collect { it.datacenter }.join(', ')}
        Inventoried IPs: ${totalIps}
        Unexpected open ports: ${totalFindings}
        Weak ciphers: ${cipherStatus}
        Job: ${env.BUILD_URL}
        ${details}
    """.stripIndent().trim()
}
