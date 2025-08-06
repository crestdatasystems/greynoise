## Playbook Backward Compatibility

- In version **3.0.0** of the connector, there is a major update due to an upgrade of the GreyNoise SDK to **v3.0.1**.  
  **⚠️ Important:** Please update any existing playbooks to use the new data paths in action results.

---

## Configure Webhooks in Connector

Starting from version **3.0.0**, the connector supports **receiving data via webhooks** from GreyNoise. Follow the steps below to configure it:

### Configure Administration Settings in Splunk SOAR

1. Enable webhook services in Splunk SOAR by following the official guide:  
   [Manage webhooks in Splunk SOAR](https://help.splunk.com/en/splunk-soar/soar-on-premises/administer-soar-on-premises/6.4.1/configure-administration-settings-in-splunk-soar-on-premises/manage-webhooks-in-splunk-soar-on-premises)
2. Adjust the rate limit for the webhook service based on the expected data volume from GreyNoise.  
   **Note:** Setting the limit too low may result in data loss.

---

### Configure Webhook in Connector Asset

1. Go to the **Asset Configuration** page of the connector.
2. Open the **Webhook Settings** tab.
3. Check **"Enable webhooks for this asset"** to enable the webhook.  
   ⚠️ **Modifing any other settings in this tab may lead to breaking webhook functionlity** .
4. Save the asset configuration. After saving, the **webhook URL** will appear under the "URL for this webhook" field.
5. **Copy the webhook URL** and use it in the GreyNoise platform.

> 🔒 **Security Note:** Treat the webhook URL as sensitive information. Do not share it, as it can be used to send data to your Splunk SOAR instance without authentication.

---

### Test Webhook (Optional)

You can test webhook ingestion using tools like **Postman** or **cURL** by sending a `POST` request to the webhook URL.

#### Test Alert Ingestion
```json
{
  "timestamp": "2023-10-05T14:55:00Z",
  "alert": {
    "id": "alert-id",
    "name": "Test Alert",
    "type": "query",
    "creator": "creator-email"
  },
  "data": [
    { "ip": "10.0.0.1", "classification": "malicious" },
    { "ip": "10.0.0.2", "classification": "suspicious" },
    { "ip": "10.0.0.3", "classification": "benign" },
    { "ip": "10.0.0.4", "classification": "unknown" }
  ],
  "viz_link": "https://viz.example.com/query/12345",
  "query_link": "https://api.example.com/v2/experimental/gnql?query=12345",
  "alert_link": "https://viz.example.com/account/alerts?alert=12345"
}
```

#### Test IP Feed Ingestion
```json
{
  "event_type": "ip-classification-change",
  "ip": "8.8.8.8",
  "new_state": "benign",
  "old_state": "unknown",
  "timestamp": "2025-08-05T10:42:38Z",
  "workspace_id": "e4a5be2e-1be0-4105-a5e2-51e6a5525fa0"
}
```

#### Test CVE Feed Ingestion
```json
{
  "cve": "CVE-2022-31717",
  "event_type": "cve-status-change",
  "metadata": {},
  "new_state": {
    "activity_seen": true,
    "benign_ip_count_10d": 0,
    "benign_ip_count_1d": 0,
    "benign_ip_count_30d": 0,
    "threat_ip_count_10d": 1,
    "threat_ip_count_1d": 1,
    "threat_ip_count_30d": 1
  },
  "old_state": {
    "activity_seen": false,
    "benign_ip_count_10d": 0,
    "benign_ip_count_1d": 0,
    "benign_ip_count_30d": 0,
    "threat_ip_count_10d": 0,
    "threat_ip_count_1d": 0,
    "threat_ip_count_30d": 0
  },
  "timestamp": "2025-08-05T10:30:16.972504375Z"
}
```

After sending the request, verify that:
- You receive a **200 OK** response with `{"status": "success"}`.
- The corresponding data is ingested into your Splunk SOAR instance.

---

### Configure Webhooks in GreyNoise

1. Follow the official documentation to configure webhook delivery methods in GreyNoise Alerts:  
   [Choosing Delivery Methods](https://docs.greynoise.io/docs/feature-alerts#choosing-delivery-methods)
2. Follow the steps in the (Configure Webhook)[https://docs.greynoise.io/docs/feature-alerts#configure-webhook] to configure webhooks in GreyNoise Feeds.

---

## Details of Ingested Data

### Alerts Ingestion

- For each alert triggered by GreyNoise, a new container/event is created in Splunk SOAR.
- **Container name format:**  
  `GreyNoise Alert: <Alert Name>: <Alert Type>: <Alert Timestamp> UTC`
- The connector adds the tag `greynoise-alert` to:
  - The container (for filtering in Playbooks)
  - Each artifact containing IP details
- Each IP is stored in a separate artifact.
- **Note:** Currently, only the **10 most recent IPs** are ingested due to a GreyNoise API limitation.

---

### Feeds Ingestion

- One container/event is created per day in Splunk SOAR for all feed events.
- **Container name format:**  
  `GreyNoise Feed: <Current Date> UTC`
- The container is tagged with `greynoise-feed`.
- Artifacts are created for:
  - IP Classification Change events (tagged with `greynoise-feed-ip`)
  - CVE Status Change events (tagged with `greynoise-feed-cve`)
  - All artifacts are additionally tagged with `greynoise-feed`
