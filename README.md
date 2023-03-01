[comment]: # "Auto-generated SOAR connector documentation"
# AlienVault OTX

Publisher: Splunk  
Connector Version: 2\.2\.0  
Product Vendor: AlienVault  
Product Name: AlienVault OTX  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.3  

This app integrates with an instance of AlienVault OTX to perform investigative actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
  
**OTX Pulses**  
Every action returns the OTX Pulses associated with the given domain, IP, file, or URL. **Pulses**
provide you with a summary of the threat, a view into the software targeted, and the related
indicators of compromise (IOCs) that can be used to detect the threats. Pulses make it easier for
you to see if your environment is exposed to a threat, if a threat is relevant to your organization,
who is behind a threat, and what a threat may be targeting in your environment.  
IOCs include:

-   IP addresses
-   Domains
-   Hostnames (subdomains)
-   Email
-   URL
-   URI
-   File Hashes: MD5, SHA1, SHA256, PEHASH, IMPHASH
-   CIDR Rules
-   File Paths
-   MUTEX name
-   CVE number


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a AlienVault OTX asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_key** |  required  | password | AlienVault OTX API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[domain reputation](#action-domain-reputation) - Queries for domain reputation information  
[ip reputation](#action-ip-reputation) - Queries for IP reputation information  
[file reputation](#action-file-reputation) - Queries for file reputation information  
[url reputation](#action-url-reputation) - Queries for URL reputation information  
[get pulses](#action-get-pulses) - Get the pulse of the provided pulse ID  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'domain reputation'
Queries for domain reputation information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.alexa | string |  `url` 
action\_result\.data\.\*\.base\_indicator\.access\_reason | string | 
action\_result\.data\.\*\.base\_indicator\.access\_type | string | 
action\_result\.data\.\*\.base\_indicator\.content | string | 
action\_result\.data\.\*\.base\_indicator\.description | string | 
action\_result\.data\.\*\.base\_indicator\.id | numeric | 
action\_result\.data\.\*\.base\_indicator\.indicator | string | 
action\_result\.data\.\*\.base\_indicator\.title | string | 
action\_result\.data\.\*\.base\_indicator\.type | string | 
action\_result\.data\.\*\.indicator | string | 
action\_result\.data\.\*\.pulse\_info\.count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.TLP | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.adversary | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.attack\_ids\.\*\.display\_name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.attack\_ids\.\*\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.attack\_ids\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.avatar\_url | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.is\_following | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.is\_subscribed | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.username | string |  `user name` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.cloned\_from | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.comment\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.created | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.description | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.downvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.export\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.follower\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.groups\.\*\.id | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.groups\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.id | string |  `otx pulse id` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.in\_group | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.CIDR | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.CVE | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-MD5 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-SHA1 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-SHA256 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FilePath | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.IPv4 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.IPv6 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.Mutex | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.SSLCertFingerprint | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.URI | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.URL | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.domain | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.email | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.hostname | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_author | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_following | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_modified | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_subscribing | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.locked | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.malware\_families\.\*\.display\_name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.malware\_families\.\*\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.malware\_families\.\*\.target | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.modified | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.modified\_text | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.adversary | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.author\_id | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.author\_name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.avatar\_url | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.cloned\_from | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.comment\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.created | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.description | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.downvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.export\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.follower\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.groups\.\*\.id | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.groups\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.groups\.\*\.pulse\_key | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.CVE | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-MD5 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-SHA1 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-SHA256 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.IPv4 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.URL | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.domain | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.email | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.hostname | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_following | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_subscribed | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_subscribing | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.locked | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.modified | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.public | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.pulse\_source | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.references | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.revision | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.tags | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.tlp | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.upvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.user\_subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.validator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.vote | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.votes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.public | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.pulse\_source | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.references | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.related\_indicator\_is\_active | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.related\_indicator\_type | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.tags | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.threat\_hunter\_has\_agents | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.threat\_hunter\_scannable | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.upvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.validator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.vote | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.votes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.references | string |  `url` 
action\_result\.data\.\*\.sections | string |  `url` 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.type\_title | string | 
action\_result\.data\.\*\.validation\.\*\.message | string | 
action\_result\.data\.\*\.validation\.\*\.name | string | 
action\_result\.data\.\*\.validation\.\*\.source | string | 
action\_result\.data\.\*\.whois | string |  `url` 
action\_result\.summary\.num\_pulses | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip reputation'
Queries for IP reputation information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IPv4 or IPv6 to query | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.accuracy\_radius | numeric | 
action\_result\.data\.\*\.area\_code | numeric | 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.base\_indicator\.access\_reason | string | 
action\_result\.data\.\*\.base\_indicator\.access\_type | string | 
action\_result\.data\.\*\.base\_indicator\.content | string | 
action\_result\.data\.\*\.base\_indicator\.description | string | 
action\_result\.data\.\*\.base\_indicator\.id | numeric | 
action\_result\.data\.\*\.base\_indicator\.indicator | string |  `ip` 
action\_result\.data\.\*\.base\_indicator\.title | string | 
action\_result\.data\.\*\.base\_indicator\.type | string | 
action\_result\.data\.\*\.charset | numeric | 
action\_result\.data\.\*\.city | string | 
action\_result\.data\.\*\.city\_data | boolean | 
action\_result\.data\.\*\.continent\_code | string | 
action\_result\.data\.\*\.country\_code | string | 
action\_result\.data\.\*\.country\_code2 | string | 
action\_result\.data\.\*\.country\_code3 | string | 
action\_result\.data\.\*\.country\_name | string | 
action\_result\.data\.\*\.dma\_code | numeric | 
action\_result\.data\.\*\.flag\_title | string | 
action\_result\.data\.\*\.flag\_url | string | 
action\_result\.data\.\*\.indicator | string |  `ip` 
action\_result\.data\.\*\.latitude | numeric | 
action\_result\.data\.\*\.longitude | numeric | 
action\_result\.data\.\*\.postal\_code | string | 
action\_result\.data\.\*\.pulse\_info\.count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.TLP | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.adversary | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.attack\_ids\.\*\.display\_name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.attack\_ids\.\*\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.attack\_ids\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.avatar\_url | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.is\_following | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.is\_subscribed | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.username | string |  `user name`  `email` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.cloned\_from | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.comment\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.created | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.description | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.downvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.export\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.follower\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.groups\.\*\.id | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.groups\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.id | string |  `otx pulse id` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.in\_group | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.CIDR | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.CVE | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-IMPHASH | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-MD5 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-PEHASH | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-SHA1 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-SHA256 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FilePath | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.IPv4 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.IPv6 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.Mutex | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.SSLCertFingerprint | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.URL | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.domain | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.email | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.hostname | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.industries | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_author | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_following | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_modified | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_subscribing | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.locked | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.modified | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.modified\_text | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.adversary | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.author\_id | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.author\_name | string |  `email` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.avatar\_url | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.cloned\_from | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.comment\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.created | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.description | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.downvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.export\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.follower\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.groups\.\*\.id | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.groups\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.groups\.\*\.pulse\_key | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.CIDR | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.CVE | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-IMPHASH | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-MD5 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-PEHASH | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-SHA1 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-SHA256 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FilePath | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.IPv4 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.Mutex | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.URL | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.domain | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.email | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.hostname | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.industries | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_following | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_subscribed | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_subscribing | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.locked | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.modified | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.public | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.pulse\_source | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.references | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.revision | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.tags | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.targeted\_countries | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.tlp | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.upvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.user\_subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.validator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.vote | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.votes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.public | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.pulse\_source | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.references | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.related\_indicator\_is\_active | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.related\_indicator\_type | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.tags | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.targeted\_countries | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.threat\_hunter\_has\_agents | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.threat\_hunter\_scannable | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.upvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.validator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.vote | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.votes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.references | string |  `url` 
action\_result\.data\.\*\.region | string | 
action\_result\.data\.\*\.reputation | numeric | 
action\_result\.data\.\*\.sections | string |  `url` 
action\_result\.data\.\*\.subdivision | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.type\_title | string | 
action\_result\.data\.\*\.whois | string |  `url` 
action\_result\.summary\.num\_pulses | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'file reputation'
Queries for file reputation information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash to query | string |  `hash`  `sha1`  `md5`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha1`  `md5`  `sha256` 
action\_result\.data\.\*\.base\_indicator\.access\_reason | string | 
action\_result\.data\.\*\.base\_indicator\.access\_type | string | 
action\_result\.data\.\*\.base\_indicator\.content | string | 
action\_result\.data\.\*\.base\_indicator\.description | string | 
action\_result\.data\.\*\.base\_indicator\.id | numeric | 
action\_result\.data\.\*\.base\_indicator\.indicator | string |  `hash`  `sha1`  `md5`  `sha256` 
action\_result\.data\.\*\.base\_indicator\.title | string | 
action\_result\.data\.\*\.base\_indicator\.type | string | 
action\_result\.data\.\*\.indicator | string |  `hash`  `sha1`  `md5`  `sha256` 
action\_result\.data\.\*\.pulse\_info\.count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.TLP | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.adversary | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.attack\_ids\.\*\.display\_name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.attack\_ids\.\*\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.attack\_ids\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.avatar\_url | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.is\_following | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.is\_subscribed | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.username | string |  `user name` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.cloned\_from | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.comment\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.created | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.description | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.downvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.export\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.follower\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.groups\.\*\.id | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.groups\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.id | string |  `otx pulse id` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.in\_group | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.CIDR | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.CVE | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-IMPHASH | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-MD5 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-SHA1 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-SHA256 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.IPv4 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.SSLCertFingerprint | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.URL | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.YARA | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.domain | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.email | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.hostname | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_author | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_following | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_modified | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_subscribing | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.locked | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.malware\_families\.\*\.display\_name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.malware\_families\.\*\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.malware\_families\.\*\.target | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.modified | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.modified\_text | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.name | string |  `md5` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.adversary | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.author\_id | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.author\_name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.avatar\_url | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.cloned\_from | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.comment\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.created | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.description | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.downvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.export\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.follower\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.groups\.\*\.id | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.groups\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.groups\.\*\.pulse\_key | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.CIDR | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.CVE | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-MD5 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-SHA1 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-SHA256 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.IPv4 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.URL | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.YARA | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.domain | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.email | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.hostname | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_following | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_subscribed | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_subscribing | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.locked | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.modified | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.public | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.pulse\_source | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.references | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.revision | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.tags | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.tlp | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.upvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.user\_subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.validator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.vote | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.votes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.public | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.pulse\_source | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.references | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.related\_indicator\_is\_active | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.related\_indicator\_type | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.tags | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.threat\_hunter\_has\_agents | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.threat\_hunter\_scannable | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.upvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.validator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.vote | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.votes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.references | string |  `url` 
action\_result\.data\.\*\.sections | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.type\_title | string | 
action\_result\.summary\.num\_pulses | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'url reputation'
Queries for URL reputation information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.alexa | string | 
action\_result\.data\.\*\.base\_indicator\.access\_reason | string | 
action\_result\.data\.\*\.base\_indicator\.access\_type | string | 
action\_result\.data\.\*\.base\_indicator\.content | string | 
action\_result\.data\.\*\.base\_indicator\.description | string | 
action\_result\.data\.\*\.base\_indicator\.id | numeric | 
action\_result\.data\.\*\.base\_indicator\.indicator | string |  `url` 
action\_result\.data\.\*\.base\_indicator\.title | string | 
action\_result\.data\.\*\.base\_indicator\.type | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.indicator | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.TLP | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.adversary | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.avatar\_url | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.is\_following | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.is\_subscribed | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.author\.username | string |  `user name` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.cloned\_from | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.comment\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.created | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.description | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.downvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.export\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.follower\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.id | string |  `otx pulse id` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.in\_group | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-MD5 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-SHA1 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.FileHash\-SHA256 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.IPv4 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.URL | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.domain | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.email | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.indicator\_type\_counts\.hostname | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_author | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_following | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_modified | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.is\_subscribing | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.locked | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.modified | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.modified\_text | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.adversary | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.author\_id | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.author\_name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.avatar\_url | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.cloned\_from | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.comment\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.created | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.description | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.downvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.export\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.follower\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.id | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-MD5 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-SHA1 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.FileHash\-SHA256 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.IPv4 | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.URL | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.domain | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.email | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.indicator\_type\_counts\.hostname | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_following | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_subscribed | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.is\_subscribing | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.locked | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.modified | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.name | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.public | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.pulse\_source | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.references | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.revision | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.tlp | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.upvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.user\_subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.validator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.vote | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.observation\.votes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.public | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.pulse\_source | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.references | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.related\_indicator\_is\_active | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.related\_indicator\_type | string | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.subscriber\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.threat\_hunter\_has\_agents | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.threat\_hunter\_scannable | boolean | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.upvotes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.validator\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.vote | numeric | 
action\_result\.data\.\*\.pulse\_info\.pulses\.\*\.votes\_count | numeric | 
action\_result\.data\.\*\.pulse\_info\.references | string |  `url` 
action\_result\.data\.\*\.pulse\_info\.related\.alienvault\.unique\_indicators | numeric | 
action\_result\.data\.\*\.pulse\_info\.related\.other\.unique\_indicators | numeric | 
action\_result\.data\.\*\.sections | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.type\_title | string | 
action\_result\.data\.\*\.whois | string | 
action\_result\.summary\.num\_pulses | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get pulses'
Get the pulse of the provided pulse ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**pulse\_id** |  required  | Pulse ID to query | string |  `otx pulse id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.pulse\_id | string |  `otx pulse id` 
action\_result\.data\.\*\.TLP | string | 
action\_result\.data\.\*\.adversary | string | 
action\_result\.data\.\*\.author\.avatar\_url | string | 
action\_result\.data\.\*\.author\.id | string | 
action\_result\.data\.\*\.author\.is\_following | boolean | 
action\_result\.data\.\*\.author\.is\_subscribed | boolean | 
action\_result\.data\.\*\.author\.username | string |  `user name` 
action\_result\.data\.\*\.author\_name | string | 
action\_result\.data\.\*\.created | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.groups\.\*\.id | numeric | 
action\_result\.data\.\*\.groups\.\*\.name | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.in\_group | boolean | 
action\_result\.data\.\*\.indicators\.\*\.content | string | 
action\_result\.data\.\*\.indicators\.\*\.created | string | 
action\_result\.data\.\*\.indicators\.\*\.description | string | 
action\_result\.data\.\*\.indicators\.\*\.expiration | string | 
action\_result\.data\.\*\.indicators\.\*\.id | numeric | 
action\_result\.data\.\*\.indicators\.\*\.indicator | string | 
action\_result\.data\.\*\.indicators\.\*\.is\_active | numeric | 
action\_result\.data\.\*\.indicators\.\*\.title | string | 
action\_result\.data\.\*\.indicators\.\*\.type | string | 
action\_result\.data\.\*\.is\_subscribing | string | 
action\_result\.data\.\*\.malware\_families | string | 
action\_result\.data\.\*\.modified | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.public | numeric | 
action\_result\.data\.\*\.revision | numeric | 
action\_result\.summary\.num\_indicators | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 