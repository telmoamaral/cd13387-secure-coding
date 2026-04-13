#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

// Network credentials
const char* ssid = "myHomeNetwork";
// telmo sensitive info
const char* password = "s3CretW1FiP4ssword";

// API server details
const char* serverName = "http://example.com/api/data";

// AWS token
// telmo sensitive info
const String aws_secret = "AKIAIMNOJVGFDXXXE4OA";

// Function to connect to the Wi-Fi network
void connectToWiFi() {
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected.");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
}

// Function to send data to the server
void sendData() {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;

    // Specify the URL
    http.begin(serverName);

    // Specify the content-type header
    http.addHeader("Content-Type", "application/json");

    // Specify the API key header
    http.addHeader("x-api-key", apiKey);

    // Prepare the JSON payload
    String jsonPayload = "{\"sensor\": \"temperature\", \"value\": 23.4}";

    // Send the request
    int httpResponseCode = http.POST(jsonPayload);

    if (httpResponseCode > 0) {
      String response = http.getString();
      Serial.println(httpResponseCode);
      Serial.println(response);
    } else {
      Serial.print("Error on sending POST: ");
      Serial.println(httpResponseCode);
    }

    http.end();
  } else {
    Serial.println("Error in WiFi connection");
  }
}

void setup() {
  Serial.begin(115200);
  connectToWiFi();
}

void loop() {
  sendData();
  delay(60000); // Send data every 60 seconds
}
