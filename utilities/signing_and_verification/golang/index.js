const axios = require("axios");
const { isHeaderValid } = require("ondc-crypto-sdk-nodejs");
const { execSync } = require('child_process');

const data = {"subscriber_id":"witslab-bap-preprod.thewitslab.com","type":"BAP"}

let search = async () => {
  try {
    // Generate header using Go crypto utility
    console.log("Generating authorization header using Go...");
    const goHeader = execSync(`export SUBSCRIBER_ID="witslab-bap-preprod.thewitslab.com" && export UNIQUE_KEY_ID="3d3412e0-54d7-475d-bcd1-6ab204985e2e" && export PRIVATE_KEY="1poOOFXWeEGFA9MpL7J0O46FapaSUTFeZrFwXe3MW672j862MD2KfaGOHLZBg6W9D8/RDySenaJTq3zZ9QV2Cg==" && go run crypto.go create_authorisation_header`, { encoding: 'utf8' }).trim();
    
    console.log("Go-generated Authorization Header:", goHeader);

    // Test the Go-generated header with the API
    console.log("\n--- Testing Go-generated header with ONDC API ---");
    try {
      const response = await axios.post(
        "https://preprod.registry.ondc.org/v2.0/lookup",
        data,
        {
          headers: {
            Authorization: goHeader,
          },
        }
      );
      console.log("✅ API Success! Response:", response.data);
    } catch (error) {
      console.log("❌ API Error:", error.response?.data || error.message);
    }

    // Validate the Go-generated header using Node.js SDK
    console.log("\n--- Header validation ---");
    const isValid = await isHeaderValid({
      header: goHeader,
      body: data,
      publicKey: "9o/OtjA9in2hjhy2QYOlvQ/P0Q8knp2iU6t82fUFdgo=",
    });
    console.log("Go header validation result:", isValid);

  } catch (error) {
    console.error("Error:", error);
  }
};

search();
