# SOC Automation with Wazuh, Shuffle, and TheHive

# Description

This SOC Automation project aims to showcase the use of automated security operations, event monitoring and alerting, as well as incident response. By leverage Wazuh EDR for event monitoring and alerting, Shuffle as the SOAR tool, and TheHive as a centralized Incident Response and Case Management Platform, alerts/detections are generated automatically and sent directly to the responder as well as automatically generating an alert in TheHive to begin the response process.

# Lab Topology

![image](https://github.com/user-attachments/assets/008db881-ae1e-4d63-8c81-f6278c16e92b)


# Tools and Utilities

- **VirtualBox**: Virtualization environment for provisioning VMs
- **Ubuntu 20.04+ or Debian ISO**: Stable Linux Distribution used to deploy Wazuh
- **Windows 10 ISO**: Acting victim Windows Machine which will be used to generate realistic security events
- **Wazuh**: Enterprise-grade and open-source EDR platform for centralized log monitoring, alerting, and rule-based analysis
- **TheHive**: Case and Incident Response platform for managing alerts and investigations
- **Shuffle**: Open-source SOAR for workflow-based security automations
- **VirusTotal**: Online security analysis tool used for analyzing files, URLs, and hashes to detect malicious signatures from an array of Antivirus engines and scanners

# Documentation

# Windows 10 VM Provision and Sysmon Install

1. Create a Windows 10 VM with at least 4GB of RAM, 1 Core CPU, and 70GB of space in VirtualBox
2. Once Windows has been setup on VirtualBox, download **Sysmon** (https://github.com/olafhartong/sysmon-modular)
3. Extract Sysmon from the ZIP folder and open PowerShell as Administrator, and install Sysmon

```powershell
.\Sysmon64.exe -i .\sysmonconfig.xml
```

1. Once the installation is complete, verify Sysmon has been installed: **Services → Applications and Services Logs → Microsoft → Windows → Sysmon64**

# Wazuh Server Provision

1. In Virtualbox, create either an Ubuntu or Debian-based VM with at least 6GB of RAM, 2 Core CPU, 100GB of storage. 
2. Mount the ISO Image that will be used in this case, Kali Purple was used
3. Once setup has been completed, open the terminal and run the following command

```powershell
curl -sO https://packages.wazuh.com/4.5/wazuh-install.sh && sudo bash ./wazuh-install.sh -a -i
```

1. After installation has been completed, a username/password will be generated for Wazuh. Be sure to store somewhere secure for future access to Wazuh 
2. Navigate to Wazuh: https://10.0.1.16:443. Be sure to use the credentials provided by Wazuh installer to login

# TheHive Dependency Install

1. Install the **dependencies** for TheHive

```powershell
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
```

2. Install **Java**

```powershell
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

3. Install **Cassandra** since that is the database used for TheHive

```powershell
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

4. Install **Elasticsearch** for indexing and searching data

```powershell
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

5. **(Optional)** Create a jvm.options file under /etc/elasticsearch/jvm.options.d and add the following config options to the file. This will optimize performance for Elasticsearch

```powershell
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
```

6. Install TheHive

```powershell
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

The hive runs on port **9000** by default and the default credentials used for TheHive are listed

```powershell
Username: admin@thehive.local
password: secret
```

## Cassandra Configuration

1. Cassandra is the DB for TheHive, so the **cassandra.yaml** file needs to be modified

```powershell
nano /etc/cassandra/cassandra.yaml
```

The following need to be changed: **listen address, port,** and **cluster name**

![image 1](https://github.com/user-attachments/assets/2ba01104-b164-41af-af7a-4c15a61170c5)


**listen_address** should be the IP of the machine that will be hosting TheHive

![image 2](https://github.com/user-attachments/assets/6829c486-afa1-41ff-ab94-5191cb1c4489)


Again, the IP of the machine hosting TheHive will be used for **rpc_address** as well

![image 3](https://github.com/user-attachments/assets/67b9cb82-4c4d-44f5-ab39-f01012177b4f)


Finally, change the seed address under **seed_provider** to the hosting machine’s IP address followed by the port Cassandra will run on (Port 7000)

![image 4](https://github.com/user-attachments/assets/fb0c61c6-54d1-4a81-9b98-bd7445a501af)


2. Once the changes have been made to cassandra.yaml file, save and stop the Cassandra service

```powershell
systemctl stop cassandra.service
```

3. Remove the old Cassandra data files since TheHive was installed using the package

```powershell
rm -rf /var/lib/cassandra/*
```

4. Start Cassandra and check the status to ensure it is running 

```powershell
systemctl start cassandra.service
systemctl status cassandra.service
```

![Screenshot_(36)](https://github.com/user-attachments/assets/f37e0db3-b4e2-446e-ad91-a5de7eb5253f)


## Configuring Elasticsearch

1. Elasticsearch is used for indexing data within TheHive, so we need to modify the config file for Elasticsearch (**elasticsearch.yml**)

![image 5](https://github.com/user-attachments/assets/721f0324-a47f-4fe1-83e4-435f06dbd04b)


Uncommonet the **node.name** field. Uncomment the **network.host** field and set the IP to the machine’s IP address

![Screenshot_(37)](https://github.com/user-attachments/assets/9409be29-f025-488f-ad60-4c8f56526120)


![image 6](https://github.com/user-attachments/assets/df814b95-5c81-4404-9649-62c9b0d70f77)


The following should also be uncommented: **http.port** and **cluster.initial_master_nodes.** Ensure only “node-1” has been input since there is only one node

![image 7](https://github.com/user-attachments/assets/1538e46f-34e0-4b5a-800c-764bd3ce919d)


2. Once the changes to elasticsearch,yml have been made, save the file and start/enable Elasticsearch service

```powershell
systemctl start elasticsearch
systemctl enable elasticsearch
```

3. Check the status of Elasticsearch to ensure it is running correctly

```powershell
systemctl status elasticsearch
```

![image 8](https://github.com/user-attachments/assets/9793bb6d-3804-439c-b1ab-9d2851834aef)


## Configuring TheHive

1. Ensure **thehive user/group** have access to the necessary file paths

```powershell
ls -la /opt/thp
```

![image 9](https://github.com/user-attachments/assets/a1e9f6a4-75a1-4d35-bc4c-2c9c13986577)


If **root** has access to the **thehive** directory, change the ownership to **thehive** for **user/group**

```powershell
chown -R thehive:thehive /opt/thp
```

![image 10](https://github.com/user-attachments/assets/dd93dccb-331b-44c7-807b-1735f0b97d9f)


2. Next, move to the config file of TheHive (**/etc/thehive/application.conf**)

```powershell
nano /etc/thehive/application.conf
```

3. In the config file, change the IP for **hostname** in the **database** and **index** section as well as the **application.baseUrl** to the machine’s IP. 

By default, TheHive has both Cortex (data enrichment and response) and MISP (Threat Intelligence Platform) enabled 

![image 11](https://github.com/user-attachments/assets/be1e9f9b-728e-450a-baa3-39ed4c5a8528)


4. Save the application.conf file and **start/enable** TheHive

```powershell
systemctl start thehive
systemctl enable thehive
```

5. Check the status of TheHive ensuring it is running with no errors

```powershell
systemctl status thehive
```

![image 12](https://github.com/user-attachments/assets/ff2e8988-71d0-47f6-b5a2-84e05447eff6)


**Note -** If you cannot access TheHive, ensure **all three** services are running: Cassandra, Elasticsearch, and TheHive). If not, TheHive will not start

6. If all three services are running, you can access TheHive by navigating to the host machine’s IP Address on port 9000

```powershell
http://10.0.1.18:9000/login
```

![image 13](https://github.com/user-attachments/assets/97f1d9c4-5b41-43e8-a687-9c9e634eaec1)


The default login credentials are provided

```powershell
Username: admin@thehive.local
password: secret
```

## Wazuh Agent Installation

1. In Wazuh, select “Add agent” and choose **Windows** as the agent will be installed on a Windows Machine. Set the **server address** to the Wazuh machine’s IP address

![image 14](https://github.com/user-attachments/assets/b306508e-4b2a-4438-8fc9-30dfa276e1bb)


2. An installation command will be generated by Wazuh. Copy it and in the Windows machine run the command in order to install the agent

![image 15](https://github.com/user-attachments/assets/97686698-98c5-4503-8530-e14bd22d96ab)


![image 16](https://github.com/user-attachments/assets/0206a43f-cd14-4a1f-83bd-8b2aba072ef3)


3. Once the agent has been installed, start the Wazuh agent, and check in **Services** if **Wazuh** is listed as a running service

```powershell
net start wazuhsvc
```

![image 17](https://github.com/user-attachments/assets/fef08fdf-dd12-45c3-b2ee-3e2eb567b4ba)


4. Back in the Wazuh manager, verify that the agent is running on the designated Windows machine and is listed as “Active” for its status

![Screenshot_(121)](https://github.com/user-attachments/assets/3fc142ac-f06c-41d1-aaa1-614f03f2715e)


# Telemetry Generation Using Mimikatz

1. In the Windows 10 Victim machine(s), go to **C:\Program Files(x86)\ossec-agent**. The file of interest is **ossec.conf.** Open with notepad. This config shows everything pertaining to Wazuh

![image 18](https://github.com/user-attachments/assets/03284a3b-60fd-4e5c-bbfc-98db33389329)


1. In the ossec.conf file under the **Log analysis** section, duplicate the <localfile></localfile> tag so now there is a duplicate of the <localfile> tag copied

![image 19](https://github.com/user-attachments/assets/896d19b9-b6d4-4b71-8bcc-9a03a690a02c)


![image 20](https://github.com/user-attachments/assets/5254d456-aaad-44e4-a446-74954b2a0153)


2. Currently the location is set to **Application** since this is a copied tag. The sysmon **Channel Name** is required copy and paste the Full Name (**Microsoft-Windows-Sysmon/Operational**) in the <location> section. Be sure to do the same with PowerShell as well

```powershell
<location>Microsoft-Windows-Sysmon/Operational</location>
```

```powershell
<location>Microsoft-Windows-PowerShell/Operational</location>
```

![image 21](https://github.com/user-attachments/assets/9862a439-65df-4bd0-ab63-11c91aff01aa)


3. Once the ossec.conf file has been modified, save it. Once the files have been changed, go to **Services** and restart the Wazuh service since modifications were mode to its configuration

![image 22](https://github.com/user-attachments/assets/bf5670fb-7097-445c-93db-259a6c1673e2)


4. Back in Wazuh, verify that the Sysmon and PowerShell logs are being sent as expected.

![image 23](https://github.com/user-attachments/assets/612952f6-29b9-44b1-9974-6f9d4fa8071e)


![image 24](https://github.com/user-attachments/assets/1e84f71a-89ac-44a4-bbca-b1c831f1af4e)


# Telemetry Generation with Mimikatz

1. On the Windows client(s) be sure to either disable or exclude specific file paths in order to download Mimikatz because it has known malicious signatures and will be disposed of by Defender

![image 25](https://github.com/user-attachments/assets/d7704291-7764-40c6-9534-7960794a4aaf)


2. Download Mimikatz and navigate to the directory where it is downloaded, then execute it (x64 directory)

![image 26](https://github.com/user-attachments/assets/e477c22d-89ab-442d-b635-29799c1270e6)


**Note -** Mimikatz was ran, but Wazuh will only log events that have a **Rule** or **Alert** set in place for that event. It does not log everything like a usual SIEM does such as Splunk or Elastic. In order to log **all** events, it can be changed in the Wazuh Manager under the **ossec.conf** file

![Screenshot_(54)](https://github.com/user-attachments/assets/583a85e2-7d78-4a05-b847-fbd15df3a9eb)


3. Go to the directory containing the **ossec.conf** file for Wazuh and open it **(/var/ossec/etc/ossec.conf**). Change the **<logall>** and **<logall_json>** from “no” to “yes” and save the file. Since changes were made to the config file, restart Wazuh

![image 27](https://github.com/user-attachments/assets/9443b89b-0311-4734-847b-00aea440107c)


![image 28](https://github.com/user-attachments/assets/4d809088-4e0b-463d-a5dd-c12db38690a6)


The configuration changes forces Wazuh to begin **archiving** all the logs into a file under the following path **/var/ossec/logs/archives**

![image 29](https://github.com/user-attachments/assets/7ab209e2-00f7-46c6-ae71-b6e426a3bb8b)


4. In order for Wazuh to being ingesting the archived logs, changes need to be made in **filebeat**

```powershell
nano /etc/filebeat/filebeat.yml 
```

Under **filebeat.modules,** change **enabled: false** to **true** under the **archives** section and restart filebeat since changes were made to it

![Screenshot_(58)](https://github.com/user-attachments/assets/96835163-ffe0-428b-95d6-888350d1fbab)


![image 30](https://github.com/user-attachments/assets/7ee3b7b7-4767-4fa4-b4ee-ece6e6499b96)


5. After updating the filebeat and ossec config files, create a new index in Wazuh which can be found under **Management → Stack Management → Index Patterns**. 

![image 31](https://github.com/user-attachments/assets/e81c3c9a-bf0c-4070-814b-c68382fc4ff3)


6. Create a new index named **wazuh-archives-***. 

![image 32](https://github.com/user-attachments/assets/b5e2396b-645c-4e2b-af0b-1ec90af2aead)


7. For the **Time field,** select **timestamp,** then select Create index pattern

![image 33](https://github.com/user-attachments/assets/80f96618-ed29-4fb7-94d4-f5fee6b6faa9)


![Screenshot_(63)](https://github.com/user-attachments/assets/2a27d6aa-0589-4ef8-b851-c4dcc000c78d)


8. Go to the **Discover** tab and filter for the newly created archive index

![image 34](https://github.com/user-attachments/assets/aefc81cd-3241-4cf6-93dd-ccdae363461c)


**Note -** Troubleshooting can be done to check and see if the logs contain the Mimikatz execution by using **cat** and **grep** on the **/var/ossec/logs/archives/archives.log**

```powershell
cat /var/ossec/logs/archives/archives.log | grep -i mimikatz
```

![Screenshot_(66)](https://github.com/user-attachments/assets/61191f03-2461-4514-812e-96f51a1b522f)


If the mimikatz telemetry is not showing up in the archives.log file, then that means no event was generated for it. Run Mimikatz again and check in Event Viewer if Sysmon is capturing the events for it now as well as checking the archives.log file again

![image 35](https://github.com/user-attachments/assets/a325169e-a003-4eff-88ad-0a920817965d)


![Screenshot_(68)](https://github.com/user-attachments/assets/e5ed0b51-8c23-458c-ab7f-4cdd52c12730)


## Creating a Custom Alert for Mimikatz

1. In Wazuh under the event generated by Mimikatz, we can begin crafting an alert based off of specific fields. In this case the **data.win.eventdata.originalFileName** will be used because if a field such as **Image** were to be used, an attacker can easily rename “Mimikatz” to “Mimicow” and the alert would’ve been bypassed.

![image 36](https://github.com/user-attachments/assets/55091739-0941-4f97-8113-8adff754f69d)


2. Rule creation can be done in the CLI or the Wazuh Manager. Rules can be found in **Management → Administration → Rules**. 

![image 37](https://github.com/user-attachments/assets/08c90592-3bc1-497e-a38d-fc9d2f58a682)


3. Once in the Rules tab, select **Manage rules files** and filter the search for “Sysmon”. In this case we are looking for rules related to **Process Creation (Event ID 1**), so select **0800_sysmon_id-1.xml**

![image 38](https://github.com/user-attachments/assets/f7b4f537-c2c3-4434-823f-18fcc4a58309)


4. Wazuh has prebuilt rules, so instead of creating a rule from scratch

![Screenshot_(73)](https://github.com/user-attachments/assets/ba7d45bc-1adf-4473-8c66-159a0e0143d9)


Example of a Rule that can be copied

![image 39](https://github.com/user-attachments/assets/a82e3bcc-c484-46d0-a00e-5451bc05059d)


5. Copy one of the rules, go back to Manage rule files, and select “Custom rules”. Edit the **local_rules.xml** file

![image 40](https://github.com/user-attachments/assets/814afb92-bd2d-4333-ba7f-4fc58f275922)


![image 41](https://github.com/user-attachments/assets/11f6d0f3-8149-4971-b03b-74dd62bfc8b8)


6. Paste in the rule that was copied.
    - Custom rules always start with “100000”, so the rule id should be anything after that
    - Level is the severity of the rule
    - Field name should be the field we are using to generate the rule based off the alert. In this case, **win.eventdata.originalFileName**
    - Type should be specified as “mimikatz” since it is searching for **specifically** “mimikatz” in the original file name
    - Remove the <Options> tag as we are collecting all the logs
    - Description is describing the alert
    - ID should refer to the MITRE ID. In this case, “T1003” since that is known for credential dumping which mimikatz does

![image 42](https://github.com/user-attachments/assets/10490c1b-fc1e-4d1e-a641-8aedd6b795e0)


7. Once the rule is created, restart the Wazuh Manager

## Testing the Custom Rule

1. Back in the Windows machine where Mimikatz is stored, rename “mimikatz.exe” in order to test if the rule is working

![image 43](https://github.com/user-attachments/assets/b50d2d79-e547-4af1-8a90-c3dd059220c6)


2. Now, execute the renamed Mimikatz

![Screenshot_(78)](https://github.com/user-attachments/assets/de13652f-9013-4a4f-85e3-32cb0e9ffada)


3. Back in Wazuh, verify that the custom rule created generated an alert based off the execution of Mimikatz

Navigate to **Modules → Security information management → Security Events**

![image 44](https://github.com/user-attachments/assets/5770a4bf-f432-4e69-a811-29cb53d9ebad)


The rule successfully triggered an alert even though we renamed “mimikatz.exe” to “pwnd.exe”

![image 45](https://github.com/user-attachments/assets/d09da22f-6e15-496b-9dea-533ea039d682)


Checking through the event generated, it can be seen that the **data.win.eventdata.originalFileName** is “mimikatz.exe”, but the **data.win.eventdata.image** is “pwnd.exe” which is why the Original File Name was chosen over the Image to base the rule off of since it maintains integrity 

![image 46](https://github.com/user-attachments/assets/e41e4b78-ddf5-444c-9d31-f0bb677a2e4d)



## Automation Using Shuffle

1. Go to [shuffler.io](http://shuffler.io) and login, or sign up for an account 

![image 47](https://github.com/user-attachments/assets/d169b033-d7f0-42e8-9edc-860c00913a03)


2. Go to **Workflows** and select the “Create New Workflow” option.

![image 48](https://github.com/user-attachments/assets/d7aa47b9-9a06-4b35-a88c-6b2154fc069a)


![image 49](https://github.com/user-attachments/assets/0ec4ea8c-bd3f-4b96-ae32-e968042c1e01)


3. Once a new workflow has been created, in the “Triggers” tab, drag a **Webhook** trigger and connect it to the “Change Me” node. Be sure to name the webhook and copy the **Webhook URI** that was generated. This webhook will be added to the ossec configuration file for Wazuh

![image 50](https://github.com/user-attachments/assets/1cdab4be-16bb-480f-8eb7-0eb3e76897a2)


4. Select the “Change Me” node. Ensure the **“**Find Actions” field is set to **Repeat back to me**. Also, under “Call”, select **Runtime arguments.** Save the workflow

![image 51](https://github.com/user-attachments/assets/fc9c432f-26a6-40e4-8609-34378415a48b)


5. In the Wazuh CLI, we need to tell it that it is going to connect to shuffle via the **Integration Tag**. Open the ossec.conf file

```powershell
nano /var/ossec/etc/ossec.conf
```

Go to the **<ossec_config>** section and create space directly under the **</global>** tag. Add the following configuration under the global tag

```powershell
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/webhook_0af8a049-f2cb-420b-af58-5ebc3c40c7df</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

![Screenshot_(88)](https://github.com/user-attachments/assets/a1840697-3977-4fe2-9e34-b41a7d662ba8)


![image 52](https://github.com/user-attachments/assets/ac0a5f3d-b97c-497d-8a98-6b4bd6dc9783)


Replace the **<hook_url>** with the webhook that was copied in Shuffle earlier, and by default it has a “Level” of 3, meaning any alert with a level of 3 will be sent to Shuffle. Change this to the **Rule ID** of mimikatz (100002)

![Screenshot_(90)](https://github.com/user-attachments/assets/a81b47ec-e5e4-49f9-969a-f38345a6a0dd)


6. Save the config file and restart Wazuh

```powershell
systemctl restart wazuh-manager.service
```

 

7. Back in the Windows machine(s), rerun Mimikatz. Go back to Shuffle, select the Webhook, and “Start”.  Click on the icon of the person running at the bottom as this will show the executions

![image 53](https://github.com/user-attachments/assets/be5459a7-c919-4027-a3a7-6dc5ec788e10)


The webhook is now working as expected and receiving the alert specifically generated by Mimikatz from Wazuh

![image 54](https://github.com/user-attachments/assets/f78540bf-4baf-490c-a65f-3ce3172d5753)


## Building the Mimikatz Workflow

**Workflow Steps**

1. Mimikatz alert is sent to Shuffle
2. Shuffle receives the Mimikatz alert and extracts the SHA256 Hash from file
3. Reputation score is checked with VirusTotal
4. Send the Details to TheHive to create an alert
5. Send email to SOC Analyst and begin Investigation

When looking at the hash value of Mimikats, it can be seen that the **hash type** is appended to the value (e.g. **sha256=hashvalue**). Only the **value** should be parsed, otherwise an error will be received in VirusTotal as an invalid query

![image 55](https://github.com/user-attachments/assets/bd001714-a07c-4355-a23b-8592458a3cb9)


1. Select the “Change Me” node, and under “Find Actions” field, select **Regex capture group**. Select In the “Input” field, select **Runtime argument** and choose **Hashes**. Under the “Regex” field, input the following value: **SHA256=([0-9A-Fa-f]{64})** and save the workflow

![image 56](https://github.com/user-attachments/assets/dacf40fe-1182-4a28-a1e5-ee31d1bf0037)


2. View executions by selecting the **Running Man** icon and under **“**Change Me”, the hash value was extracted excluding the hash type (e.g. sha256=). Rename “Change Me” to “SHA256_Regex”

![image 57](https://github.com/user-attachments/assets/a5b89208-8932-4d70-9afe-436cff5d66d2)


### Integrating VirusTotal

1. Go to VirusTotal and login or create an account in order to attain an API for VirusTotal.

![Screenshot_(96)](https://github.com/user-attachments/assets/e2c0d424-314e-48da-8b03-09c644bda581)


Copy the key and in Shuffle under “Apps”, select **VirusTotal,** then drag the app onto the workflow. Will automatically connect 

![image 58](https://github.com/user-attachments/assets/5a641baa-9e1a-411c-a122-c970eabd63d0)


In the “VirusTotal” node, for the “Find Actions” field, select **Get a hash report**. Next, select **“**Authenticate VirusTotal v3” and paste in the VirusTotal API Key

![Screenshot_(98)](https://github.com/user-attachments/assets/c2ae7405-c180-4c57-beb1-7e37a0e4a08b)


In the “Id” field, the SHA256 Regex list should be selected for the field, which is used to parse out the value of only the hash

![image 59](https://github.com/user-attachments/assets/f625f99a-54d3-4de0-b212-84f24d3379ce)


Save the workflow and rerun it. Scrolling to “last_analysis_stats: malicious”, there is 64 scanners marked mimikatz SHA Hash as malicious

![image 60](https://github.com/user-attachments/assets/53c48bd7-7a71-4705-b3bb-a1532f773690)


### Integrating TheHive

The details generated by the workflow should now be sent to TheHive for case management

1. In Shuffle, add “TheHive” app to the workflow board 

![image 61](https://github.com/user-attachments/assets/e6afc34c-9841-42db-9516-825a6f421205)

2. Log into TheHive and create a new organization and user for for the organization

![Screenshot_(101)](https://github.com/user-attachments/assets/49247559-4fe9-4ad5-95aa-c522422f8481)


Now that the organization has been created, select it and add a normal user to the org; (+) button. Create a service account user as well

![Screenshot_(102)](https://github.com/user-attachments/assets/03b01f7e-a08c-4936-81e0-b6cf423ef818)


![Screenshot_(103)](https://github.com/user-attachments/assets/0d9da716-a4c7-4f95-91f9-7f56e64a3fdc)


Set new passwords for the accounts by select “Preview” → “Set a new password”. For the Shuffle account, generate an API Key and store it safely as it will be used to authenticate with Shuffle

![Screenshot_(104)](https://github.com/user-attachments/assets/9295fc25-0b7e-4e62-b832-992ff91842c1)


![image 62](https://github.com/user-attachments/assets/3cb48921-1951-43b6-976b-53d417f66659)


3. Logout from the admin account and login with the normal user account created earlier

![Screenshot_(106)](https://github.com/user-attachments/assets/80c1de67-4d8d-4e46-ad19-cb3535e5d392)


4. Back in Shuffle, we will begin configuration to work with TheHive. Select TheHive node and click the “Authenticate TheHive” button

![image 63](https://github.com/user-attachments/assets/546a74c7-25cc-4470-855d-ecedfd66c02a)


Enter the API key generated in TheHive for the service account as well as the IP address of TheHive machine along with its port

![Screenshot_(108)](https://github.com/user-attachments/assets/c313636b-6229-4803-a555-b8280304e8e2)


Under the “Find actions” field, select **Create alert**. There are multiple fields that need to be modified, upon completion of field inputs, the JSON data should look as follows:

```powershell
{
  "description": "Mimikatz Detected on host: DESKTOP-HS8N3J7",
  "externallink": "",
  "flag": false,
  "pap": 2,
  "severity": "2",
  "source": "Wazuh",
  "sourceRef": "Rule:100002",
  "status": "New",
  "summary": "Mimikatz activity detected on Host: $exec.text.win.system.computer and the Process ID is: $exec.text.win.eventdata.processId and the CommandLine is: $exec.text.win.eventdata.commandLine",
  "tags": [
    "T1003"
  ],
  "title": "Mimikatz Detection Alert",
  "tlp": 2,
  "type": "Internal"
}
```

5. Once the following fields have been populated, rerun the workflow. The workflow successfully ran utilizing the API generated for the service account for shuffle and an alert was generated

![Screenshot_(109)](https://github.com/user-attachments/assets/bee336e7-890f-4458-82b6-a8920279f89d)


![Screenshot_(110)](https://github.com/user-attachments/assets/88b5e3a6-b395-40f6-9f31-ca2fb54605cd)


If we view the details of the alert, it contains everything that was specified in Shuffle such as: **Title, Description, Tags, Source.**

![Screenshot_(111)](https://github.com/user-attachments/assets/f4aa0679-2629-4b2d-b135-c357e2ce7ff0)


### Integrating Email Into the Workflow

1. In the “Apps” tab of Shuffle, drag the “Email” node onto the workflow and connect it to the VirusTotal Node. 

![image 64](https://github.com/user-attachments/assets/3d991edb-5f11-494e-8618-d4ca042f1397)


Configure the desired settings of the Email node for “Recipients”, “Subject”, and “Body”. Once the fields have been modified, save the workflow

![image 65](https://github.com/user-attachments/assets/6c58d553-78a6-49c4-83d6-f8f50545cc38)


![image 66](https://github.com/user-attachments/assets/1720a7e1-cf31-4e27-b136-d596e4c131ec)


2. Run the workflow and verify that the email was received

![Screenshot_(116)](https://github.com/user-attachments/assets/9ca292f1-a63c-4e5a-ac39-048e65354dbb)


The workflow was successful and an email pertaining to the alert was sent successfully with information regarding the alert

# Conclusion

This project demonstrates the successful provision and integration of Wazuh, Shuffle, and TheHive as well as streamlining the use case of an automation workflow with SOAR. By leveraging EDR, SOAR, and an IR platform, a proper pipeline was automated from detection in Wazuh, automation with Shuffle, enrichment with VirusTotal, and alerting/Incident Response with TheHive. By doing so, efficiency as well as response time was enhanced, and manual processing was reduced significantly.
