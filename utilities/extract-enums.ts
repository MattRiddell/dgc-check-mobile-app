// Grabs the latest definitions
const axios = require("axios")
if (!process.argv[2]) {
  console.log("Run like this: node utilities/extract-enums.ts test-manf")
} else {
  axios.get("https://raw.githubusercontent.com/ehn-dcc-development/ehn-dcc-schema/release/1.3.0/valuesets/" + process.argv[2] + ".json").then(r => {
    if (r) {
      for (const [key, value] of Object.entries(r.data.valueSetValues)) {
        console.log(`"${key}",`);
      }
    }

  });
}

