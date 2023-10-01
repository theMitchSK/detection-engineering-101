import requests
import os
import tomllib

url = "https://detectionengineering101-02753e.kb.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules"
api_key = os.environ['ELASTIC_KEY']
headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": "ApiKey " + api_key
}

data = ""

for root, dirs, files in os.walk("detections/"): #this is our working folder, needed to switch from \ to /
    for file in files:
        data = "{\n" #this starts us off by creating a line break
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)

                if alert['rule']['type'] == "query": #query-based alert
                    required_fields = ['author','description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query']
                elif alert['rule']['type'] == "eql": #event correlation alert
                    required_fields = ['author','description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'language']
                elif alert['rule']['type'] == "threshold": #threshold-based alert
                    required_fields = ['author','description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'threshold']
                else:
                     print("Unsupported rule type found in: " + full_path)
                     break
                    
                for field in alert['rule']:
                    if field in required_fields: #based on type
                        if type(alert['rule'][field]) == list:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                        elif type(alert['rule'][field]) == str:
                            if field == 'description':
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n", " ").replace("\"","\\\"").replace("\\","\\\\") + "\"," + "\n" #added last replace of \ with \\ as JSON doesn't like the \ in 'Windows\Temp'
                            elif field == 'query':
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\\", "\\\\").replace("\"","\\\"").replace("\n", " ") + "\"," + "\n" #doesn't like the \ in the query field
                            else:
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n", " ").replace("\"","\\\"") + "\"," + "\n"
                        elif type(alert['rule'][field]) == int:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + "," + "\n"
                        elif type(alert['rule'][field]) == dict:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                data += "  \"enabled\": true\n}"

            rule_id = (alert['rule']['rule_id'])
            url = url + "?rule_id=" + rule_id
            

            #print(data)
            
            elastic_data = requests.put(url, headers=headers, data=data).json()
            print(elastic_data)