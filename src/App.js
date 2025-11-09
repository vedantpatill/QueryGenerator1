import React, { useState } from "react";
import {
  Search,
  Copy,
  Check,
  AlertTriangle,
  Shield,
  Database,
} from "lucide-react";

const ThreatHuntQueryGenerator = () => {
  const [platform, setPlatform] = useState("splunk");
  const [technique, setTechnique] = useState("");
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState(false);
  const [tips, setTips] = useState("");

  const platforms = [
    { id: "splunk", name: "Splunk SPL" },
    { id: "kql", name: "Microsoft KQL" },
    { id: "elastic", name: "Elastic EQL" },
    { id: "sigma", name: "Sigma Rule" },
  ];

  const techniques = [
    { id: "T1053.005", name: "Scheduled Task", tactic: "Persistence" },
    { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
    { id: "T1003.001", name: "LSASS Dumping", tactic: "Credential Access" },
    { id: "T1071.001", name: "C2 Beaconing", tactic: "Command and Control" },
    {
      id: "T1021.001",
      name: "RDP Lateral Movement",
      tactic: "Lateral Movement",
    },
    { id: "T1136.001", name: "Local Account Creation", tactic: "Persistence" },
  ];

  const queries = {
    "T1053.005": {
      splunk: `index=windows (EventCode=4698 OR EventCode=1)
| eval suspicious=if(match(TaskContent,"(?i)(powershell|cmd|wscript)"),1,0)
| where suspicious=1
| stats count by ComputerName,TaskName,User`,
      kql: `SecurityEvent
| where EventID in (4698,4699)
| where CommandLine has_any ("powershell","cmd","wscript")
| project TimeGenerated,Computer,Account,TaskName,CommandLine
| summarize Count=count() by Computer,TaskName`,
      elastic: `process where event.type == "start" and
  process.parent.name : "svchost.exe" and
  process.name : ("powershell.exe","cmd.exe")`,
      sigma: `title: Suspicious Scheduled Task
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
    TaskContent|contains: ['powershell','cmd']
  condition: selection
level: medium`,
    },
    "T1059.001": {
      splunk: `index=windows EventCode=4104
| eval encoded=if(match(ScriptBlockText,"(?i)-enc"),1,0)
| eval susp=if(match(ScriptBlockText,"(?i)(invoke-|downloadstring|bypass)"),1,0)
| where encoded=1 OR susp=1
| stats count by ComputerName,User,ScriptBlockText`,
      kql: `Event
| where EventID == 4104
| where EventData has_any ("-enc","invoke-","downloadstring","bypass")
| project TimeGenerated,Computer,User,EventData
| summarize Count=count() by Computer,User`,
      elastic: `process where process.name : "powershell.exe" and
  process.args : ("-enc*","*invoke-*","*downloadstring*","*bypass*")`,
      sigma: `title: Suspicious PowerShell
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains: ['-enc','invoke-','bypass']
  condition: selection
level: high`,
    },
    "T1003.001": {
      splunk: `index=windows EventCode=10 TargetImage="*\\lsass.exe"
| eval susp=if(match(SourceImage,"(?i)(procdump|mimikatz|powershell)"),1,0)
| where susp=1
| stats count by ComputerName,SourceImage,GrantedAccess`,
      kql: `SecurityEvent
| where EventID == 10
| where Process has "lsass.exe"
| where ProcessName has_any ("procdump","powershell","rundll32")
| project TimeGenerated,Computer,ProcessName,AccessMask`,
      elastic: `process where process.name : ("procdump.exe","sqldumper.exe") and
  process.args : "lsass*"`,
      sigma: `title: LSASS Memory Access
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess: ['0x1010','0x1410']
  condition: selection
level: high`,
    },
    "T1071.001": {
      splunk: `index=proxy
| stats count dc(bytes_out) as uniq avg(bytes_out) as avg by src_ip,dest_ip
| where uniq<3 AND avg<500 AND count>50
| eval score=if(count>50,"High","Medium")`,
      kql: `CommonSecurityLog
| summarize Count=count(),AvgBytes=avg(SentBytes),Uniq=dcount(SentBytes) 
  by SourceIP,DestinationIP,bin(TimeGenerated,5m)
| where Count>20 and Uniq<3 and AvgBytes<500`,
      elastic: `network where destination.port in (80,443) and
  network.bytes < 500`,
      sigma: `title: C2 Beaconing
logsource:
  category: proxy
detection:
  selection:
    sc-bytes: '<500'
  timeframe: 5m
  condition: selection | count() > 20
level: medium`,
    },
    "T1021.001": {
      splunk: `index=windows EventCode=4624 LogonType=10
| stats count dc(src_ip) as sources by dest,user
| where sources>3 OR count>10
| eval risk=if(count>20,"High","Medium")`,
      kql: `SecurityEvent
| where EventID == 4624 and LogonType == 10
| summarize Count=count(),Sources=dcount(IpAddress) 
  by Computer,Account,bin(TimeGenerated,1h)
| where Sources>3 or Count>10`,
      elastic: `authentication where event.action : "logged-in" and
  winlog.logon.type == "RemoteInteractive"`,
      sigma: `title: Suspicious RDP
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 10
  timeframe: 1h
  condition: selection | count() > 10
level: medium`,
    },
    "T1136.001": {
      splunk: `index=windows (EventCode=4720 OR EventCode=4732)
| eval susp=if(match(TargetUserName,"(?i)(admin|test|temp|\\$)"),1,0)
| where susp=1
| stats count by ComputerName,SubjectUserName,TargetUserName`,
      kql: `SecurityEvent
| where EventID in (4720,4732)
| where Account has_any ("admin","test","temp","$")
| project TimeGenerated,Computer,SubjectAccount,TargetAccount`,
      elastic: `iam where event.action in ("create-user","added-member-to-group") and
  user.name : ("*admin*","*test*","*temp*")`,
      sigma: `title: Suspicious Account Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
    TargetUserName|contains: ['admin','test','temp']
  condition: selection
level: medium`,
    },
  };

  const huntingTips = {
    "T1053.005": `🎯 Scheduled Task Hunting:
• Baseline legitimate tasks first
• Look for tasks from non-admin users
• Check for encoded commands
• Focus on tasks running from temp directories
• Monitor tasks created outside business hours`,
    "T1059.001": `🎯 PowerShell Hunting:
• Enable Script Block Logging (Event 4104)
• Decode base64 commands
• Look for download cradles (iwr, downloadstring)
• Monitor execution policy bypasses
• Check for obfuscation patterns`,
    "T1003.001": `🎯 LSASS Dumping Hunting:
• Monitor Sysmon Event ID 10
• Look for procdump, mimikatz variants
• Check for comsvcs.dll + rundll32
• Focus on access masks 0x1010, 0x1410
• Monitor .dmp file creation`,
    "T1071.001": `🎯 C2 Beaconing Hunting:
• Baseline normal network patterns
• Look for consistent intervals (5min, 10min)
• Check for small consistent packet sizes
• Analyze connection frequency
• Monitor traffic during off-hours`,
    "T1021.001": `🎯 RDP Hunting:
• Focus on LogonType 10
• Track failed attempts (Event 4625)
• Monitor connections from external IPs
• Check for lateral movement patterns
• Look for connections during odd hours`,
    "T1136.001": `🎯 Account Creation Hunting:
• Monitor Event IDs 4720, 4732
• Check for suspicious naming patterns
• Track admin group additions
• Monitor off-hours creation
• Verify account usage patterns`,
  };

  const generate = () => {
    if (!technique) {
      alert("Select a technique first");
      return;
    }
    setQuery(queries[technique]?.[platform] || "Not available");
    setTips(huntingTips[technique] || "");
  };

  const copy = () => {
    navigator.clipboard.writeText(query);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-3">
            <Shield className="w-10 h-10 text-purple-400" />
            <h1 className="text-3xl font-bold text-white">
              Threat Hunt Query Generator
            </h1>
          </div>
          <p className="text-purple-200">
            Generate queries mapped to MITRE ATT&CK
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          <div className="space-y-4">
            <div className="bg-slate-800 rounded-lg p-4 border border-purple-500/30">
              <label className="flex items-center gap-2 text-purple-300 font-semibold mb-2">
                <Database className="w-4 h-4" />
                Platform
              </label>
              <select
                value={platform}
                onChange={(e) => setPlatform(e.target.value)}
                className="w-full bg-slate-700 text-white border border-purple-500/50 rounded px-3 py-2"
              >
                {platforms.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="bg-slate-800 rounded-lg p-4 border border-purple-500/30">
              <label className="flex items-center gap-2 text-purple-300 font-semibold mb-2">
                <AlertTriangle className="w-4 h-4" />
                Technique
              </label>
              <select
                value={technique}
                onChange={(e) => setTechnique(e.target.value)}
                className="w-full bg-slate-700 text-white border border-purple-500/50 rounded px-3 py-2"
              >
                <option value="">Select...</option>
                {techniques.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.id} - {t.name}
                  </option>
                ))}
              </select>
              {technique && (
                <div className="mt-3 p-3 bg-slate-700/50 rounded text-sm">
                  <div className="text-purple-300">Tactic:</div>
                  <div className="text-white">
                    {techniques.find((t) => t.id === technique)?.tactic}
                  </div>
                </div>
              )}
            </div>

            <button
              onClick={generate}
              className="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-bold py-3 rounded flex items-center justify-center gap-2"
            >
              <Search className="w-5 h-5" />
              Generate Query
            </button>
          </div>

          <div className="md:col-span-2 space-y-4">
            {query && (
              <>
                <div className="bg-slate-800 rounded-lg p-4 border border-purple-500/30">
                  <div className="flex justify-between items-center mb-3">
                    <h2 className="text-lg font-bold text-purple-300 flex items-center gap-2">
                      <Search className="w-5 h-5" />
                      Generated Query
                    </h2>
                    <button
                      onClick={copy}
                      className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-3 py-2 rounded text-sm"
                    >
                      {copied ? (
                        <Check className="w-4 h-4" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                      {copied ? "Copied!" : "Copy"}
                    </button>
                  </div>
                  <div className="bg-slate-900 rounded p-3">
                    <pre className="text-green-400 text-sm overflow-x-auto whitespace-pre-wrap">
                      {query}
                    </pre>
                  </div>
                </div>

                <div className="bg-slate-800 rounded-lg p-4 border border-purple-500/30">
                  <h2 className="text-lg font-bold text-purple-300 mb-3 flex items-center gap-2">
                    <Shield className="w-5 h-5" />
                    Hunting Tips
                  </h2>
                  <div className="bg-slate-900 rounded p-3">
                    <pre className="text-gray-300 text-sm whitespace-pre-wrap">
                      {tips}
                    </pre>
                  </div>
                </div>
              </>
            )}

            {!query && (
              <div className="bg-slate-800 rounded-lg p-6 border border-purple-500/30">
                <h2 className="text-xl font-bold text-purple-300 mb-4">
                  🚀 Quick Start
                </h2>
                <div className="space-y-3 text-gray-300 text-sm">
                  <div className="flex gap-3">
                    <div className="bg-purple-600 rounded-full w-7 h-7 flex items-center justify-center font-bold flex-shrink-0">
                      1
                    </div>
                    <div>
                      <div className="font-semibold text-white">
                        Select Platform
                      </div>
                      <div>Choose your SIEM (Splunk, KQL, Elastic, Sigma)</div>
                    </div>
                  </div>
                  <div className="flex gap-3">
                    <div className="bg-purple-600 rounded-full w-7 h-7 flex items-center justify-center font-bold flex-shrink-0">
                      2
                    </div>
                    <div>
                      <div className="font-semibold text-white">
                        Pick Technique
                      </div>
                      <div>Select from MITRE ATT&CK mapped techniques</div>
                    </div>
                  </div>
                  <div className="flex gap-3">
                    <div className="bg-purple-600 rounded-full w-7 h-7 flex items-center justify-center font-bold flex-shrink-0">
                      3
                    </div>
                    <div>
                      <div className="font-semibold text-white">
                        Generate & Hunt
                      </div>
                      <div>Get production-ready queries with hunting tips</div>
                    </div>
                  </div>
                  <div className="mt-4 p-3 bg-purple-900/30 rounded border border-purple-500/30">
                    <div className="font-semibold text-purple-300 mb-2">
                      💡 Pro Tips:
                    </div>
                    <ul className="text-xs space-y-1">
                      <li>• Baseline your environment first</li>
                      <li>• Correlate across multiple data sources</li>
                      <li>• Document false positives</li>
                      <li>• Start with high-fidelity detections</li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatHuntQueryGenerator;
