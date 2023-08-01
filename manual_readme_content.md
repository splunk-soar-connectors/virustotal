[comment]: # " File: README.md"
[comment]: # " Copyright (c) 2016-2022 Splunk Inc."
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
**Playbook Backward Compatibility**

-   One old asset parameter is removed and new asset parameter has been added to the asset
    configuration given below. Hence, it is requested to the end-user please update their existing
    playbooks and provide values to this new parameter to ensure the correct functioning of the
    playbooks created on the earlier versions of the app.

      

    -   **For version 2.2.X :**

          

        -   Test Connectivity - **requests_per_minute** parameter has been added
        -   Test Connectivity - **rate_limit** parameter has been removed.

    -   **For version 2.1.X :**

          

        -   Test Connectivity - **rate_limit** parameter has been added

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Virustotal server. Below are the
default ports used by Splunk SOAR.

|         SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |
