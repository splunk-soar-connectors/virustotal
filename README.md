**Playbook Backward Compatibility**

One old asset parameter is removed and new asset parameter has been added to the asset configuration given below. Hence, it is requested to the end-user please update their existing playbooks and provide values to this new parameter to ensure the correct functioning of the playbooks created on the earlier versions of the app.

*   **For version 2.2.X :**

    *   Test Connectivity - **requests\_per\_minute** parameter has been added
    *   Test Connectivity - **rate\_limit** parameter has been removed.

*   **For version 2.1.X :**

    *   Test Connectivity - **rate\_limit** parameter has been added

### Port Information
The app uses HTTP/ HTTPS protocol for communicating with the Virustotal server. Below are the default ports used by Splunk SOAR.

SERVICE NAME | TRANSPORT PROTOCOL | PORT
------------ | ------------------ | ----
**http** | tcp | 80
**https** | tcp | 443